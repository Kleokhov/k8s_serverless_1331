/*
Copyright 2014 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package scheduler

import (
	"container/heap"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sort"
	"sync/atomic"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	podutil "k8s.io/kubernetes/pkg/api/v1/pod"
	"k8s.io/kubernetes/pkg/apis/core/validation"
	"k8s.io/kubernetes/pkg/scheduler/framework"
	"k8s.io/kubernetes/pkg/scheduler/framework/parallelize"
	"k8s.io/kubernetes/pkg/scheduler/metrics"
	"k8s.io/kubernetes/pkg/scheduler/util"
	utiltrace "k8s.io/utils/trace"

	"lambda/pkg/scheduler/backend/awsstore"
)

const (
	// Percentage of plugin metrics to be sampled.
	pluginMetricsSamplePercent = 10
	// minFeasibleNodesToFind is the minimum number of nodes that would be scored
	// in each scheduling cycle. This is a semi-arbitrary value to ensure that a
	// certain minimum of nodes are checked for feasibility. This in turn helps
	// ensure a minimum level of spreading.
	minFeasibleNodesToFind = 100
	// minFeasibleNodesPercentageToFind is the minimum percentage of nodes that
	// would be scored in each scheduling cycle. This is a semi-arbitrary value
	// to ensure that a certain minimum of nodes are checked for feasibility.
	// This in turn helps ensure a minimum level of spreading.
	minFeasibleNodesPercentageToFind = 5
	// numberOfHighestScoredNodesToReport is the number of node scores
	// to be included in ScheduleResult.
	numberOfHighestScoredNodesToReport = 3
)

type scheduleOneOutcome struct {
	consumed bool
	binding  *pendingBindingDispatch
}

// ScheduleOne does the entire scheduling workflow for a single pod. It is serialized on the scheduling algorithm's host fitting.
func (sched *Scheduler) ScheduleOne(ctx context.Context) {
	outcome := sched.scheduleOne(ctx)
	if outcome.binding != nil {
		if err := sched.dispatchBinding(ctx, outcome.binding.req); err != nil {
			sched.handleBindingDispatchError(ctx, outcome.binding.fwk, outcome.binding.podInfo, outcome.binding.start, err)
		}
	}
}

// ScheduleUpTo drains up to maxPods from the scheduling queue in one caller
// invocation. It stops early when the queue is empty or the context is done.
func (sched *Scheduler) ScheduleUpTo(ctx context.Context, maxPods int) int {
	if maxPods <= 0 {
		return 0
	}

	processed := 0
	pendingBindings := make([]pendingBindingDispatch, 0, min(maxPods, 10))
	flushBindings := func() {
		if len(pendingBindings) == 0 {
			return
		}
		sched.dispatchBindingBatch(ctx, pendingBindings)
		pendingBindings = pendingBindings[:0]
	}

	for processed < maxPods {
		if err := ctx.Err(); err != nil {
			klog.FromContext(ctx).Error(err, "Stopping schedule drain because context is done", "processedPods", processed, "maxPods", maxPods)
			break
		}
		outcome := sched.scheduleOne(ctx)
		if !outcome.consumed {
			break
		}
		processed++
		if outcome.binding != nil {
			pendingBindings = append(pendingBindings, *outcome.binding)
			if len(pendingBindings) >= 10 {
				flushBindings()
			}
		}
	}
	flushBindings()
	return processed
}

// scheduleOne reports whether it consumed a pod from the queue, even if that
// pod later failed scheduling. Successful scheduling returns a pending binding
// handoff for the caller to dispatch.
func (sched *Scheduler) scheduleOne(ctx context.Context) scheduleOneOutcome {
	logger := klog.FromContext(ctx)
	podInfo, err := sched.NextPod(logger)
	if err != nil {
		if errors.Is(err, awsstore.ErrQueueEmpty) {
			logger.V(4).Info("Scheduling queue is empty")
			return scheduleOneOutcome{}
		}
		logger.Error(err, "Error while retrieving next pod from scheduling queue")
		return scheduleOneOutcome{}
	}
	// pod could be nil when schedulerQueue is closed
	if podInfo == nil || podInfo.Pod == nil {
		return scheduleOneOutcome{}
	}

	pod := podInfo.Pod
	logger = klog.LoggerWithValues(logger, "pod", klog.KObj(pod))
	ctx = klog.NewContext(ctx, logger)
	logger.V(4).Info("About to try and schedule pod", "pod", klog.KObj(pod))

	fwk, err := sched.frameworkForPod(pod)
	if err != nil {
		// This shouldn't happen, because we only accept for scheduling the pods
		// which specify a scheduler name that matches one of the profiles.
		logger.Error(err, "Error occurred")
		sched.SchedulingQueue.Done(pod.UID)
		return scheduleOneOutcome{consumed: true}
	}
	if sched.skipPodSchedule(ctx, fwk, pod) {
		// We don't put this Pod back to the queue, but we have to cleanup the in-flight pods/events.
		sched.SchedulingQueue.Done(pod.UID)
		return scheduleOneOutcome{consumed: true}
	}

	logger.V(3).Info("Attempting to schedule pod", "pod", klog.KObj(pod))

	// Synchronously attempt to find a fit for the pod.
	start := time.Now()
	state := framework.NewCycleState()
	state.SetRecordPluginMetrics(rand.Intn(100) < pluginMetricsSamplePercent)
	features := sched.featuresForPod(pod)

	var podsToActivate *framework.PodsToActivate
	if features.needsPodsToActivate() {
		// Only create activation bookkeeping when some enabled extension point can use it.
		podsToActivate = framework.NewPodsToActivate()
		state.Write(framework.PodsToActivateKey, podsToActivate)
	}

	schedulingCycleCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	scheduleResult, assumedPodInfo, status := sched.schedulingCycle(schedulingCycleCtx, state, fwk, podInfo, start, podsToActivate)
	if !status.IsSuccess() {
		sched.FailureHandler(schedulingCycleCtx, fwk, assumedPodInfo, status, scheduleResult.nominatingInfo, start)
		return scheduleOneOutcome{consumed: true}
	}

	logger.Info(
		"Pod assumed and ready to be handed to binder",
		"suggestedHost", scheduleResult.SuggestedHost,
		"evaluatedNodes", scheduleResult.EvaluatedNodes,
		"feasibleNodes", scheduleResult.FeasibleNodes,
		"attempts", assumedPodInfo.Attempts,
	)

	return scheduleOneOutcome{
		consumed: true,
		binding: &pendingBindingDispatch{
			req:     newBindingRequest(scheduleResult, assumedPodInfo, start),
			fwk:     fwk,
			podInfo: assumedPodInfo,
			start:   start,
		},
	}
}

var clearNominatedNode = &framework.NominatingInfo{NominatingMode: framework.ModeOverride, NominatedNodeName: ""}

// schedulingCycle tries to schedule a single Pod.
func (sched *Scheduler) schedulingCycle(
	ctx context.Context,
	state *framework.CycleState,
	fwk framework.Framework,
	podInfo *framework.QueuedPodInfo,
	start time.Time,
	podsToActivate *framework.PodsToActivate,
) (ScheduleResult, *framework.QueuedPodInfo, *framework.Status) {
	logger := klog.FromContext(ctx)
	pod := podInfo.Pod
	scheduleResult, err := sched.SchedulePod(ctx, fwk, state, pod)
	if err != nil {
		defer func() {
			metrics.SchedulingAlgorithmLatency.Observe(metrics.SinceInSeconds(start))
		}()
		if err == ErrNoNodesAvailable {
			status := framework.NewStatus(framework.UnschedulableAndUnresolvable).WithError(err)
			return ScheduleResult{nominatingInfo: clearNominatedNode}, podInfo, status
		}

		fitError, ok := err.(*framework.FitError)
		if !ok {
			logger.Error(err, "Error selecting node for pod", "pod", klog.KObj(pod))
			return ScheduleResult{nominatingInfo: clearNominatedNode}, podInfo, framework.AsStatus(err)
		}

		// SchedulePod() may have failed because the pod would not fit on any host, so we try to
		// preempt, with the expectation that the next time the pod is tried for scheduling it
		// will fit due to the preemption. It is also possible that a different pod will schedule
		// into the resources that were preempted, but this is harmless.

		if !fwk.HasPostFilterPlugins() {
			logger.V(3).Info("No PostFilter plugins are registered, so no preemption will be performed")
			return ScheduleResult{}, podInfo, framework.NewStatus(framework.Unschedulable).WithError(err)
		}

		// Run PostFilter plugins to attempt to make the pod schedulable in a future scheduling cycle.
		result, status := fwk.RunPostFilterPlugins(ctx, state, pod, fitError.Diagnosis.NodeToStatus)
		msg := status.Message()
		fitError.Diagnosis.PostFilterMsg = msg
		if status.Code() == framework.Error {
			logger.Error(nil, "Status after running PostFilter plugins for pod", "pod", klog.KObj(pod), "status", msg)
		} else {
			logger.V(5).Info("Status after running PostFilter plugins for pod", "pod", klog.KObj(pod), "status", msg)
		}

		var nominatingInfo *framework.NominatingInfo
		if result != nil {
			nominatingInfo = result.NominatingInfo
		}
		return ScheduleResult{nominatingInfo: nominatingInfo}, podInfo, framework.NewStatus(framework.Unschedulable).WithError(err)
	}

	metrics.SchedulingAlgorithmLatency.Observe(metrics.SinceInSeconds(start))
	// Tell the cache to assume that a pod now is running on a given node, even though it hasn't been bound yet.
	// This allows us to keep scheduling without waiting on binding to occur.
	assumedPodInfo := podInfo.DeepCopy()
	assumedPod := assumedPodInfo.Pod
	// assume modifies `assumedPod` by setting NodeName=scheduleResult.SuggestedHost
	err = sched.assume(logger, assumedPod, scheduleResult.SuggestedHost)
	if err != nil {
		// This is most probably result of a BUG in retrying logic.
		// We report an error here so that pod scheduling can be retried.
		// This relies on the fact that Error will check if the pod has been bound
		// to a node and if so will not add it back to the unscheduled pods queue
		// (otherwise this would cause an infinite loop).
		return ScheduleResult{nominatingInfo: clearNominatedNode}, assumedPodInfo, framework.AsStatus(err)
	}

	// At the end of a successful scheduling cycle, pop and move up Pods if needed.
	if podsToActivate != nil && len(podsToActivate.Map) != 0 {
		sched.SchedulingQueue.Activate(logger, podsToActivate.Map)
		// Clear the entries after activation.
		podsToActivate.Map = make(map[string]*v1.Pod)
	}

	return scheduleResult, assumedPodInfo, nil
}

func (sched *Scheduler) frameworkForPod(pod *v1.Pod) (framework.Framework, error) {
	fwk, ok := sched.Profiles[pod.Spec.SchedulerName]
	if !ok {
		return nil, fmt.Errorf("profile not found for scheduler name %q", pod.Spec.SchedulerName)
	}
	return fwk, nil
}

func (sched *Scheduler) featuresForPod(pod *v1.Pod) profileFeatures {
	if pod == nil {
		return profileFeatures{}
	}
	return sched.profileFeatures[pod.Spec.SchedulerName]
}

// skipPodSchedule returns true if we could skip scheduling the pod for specified cases.
func (sched *Scheduler) skipPodSchedule(ctx context.Context, fwk framework.Framework, pod *v1.Pod) bool {
	// Case 1: pod is being deleted.
	if pod.DeletionTimestamp != nil {
		fwk.EventRecorder().Eventf(pod, nil, v1.EventTypeWarning, "FailedScheduling", "Scheduling", "skip schedule deleting pod: %v/%v", pod.Namespace, pod.Name)
		klog.FromContext(ctx).V(3).Info("Skip schedule deleting pod", "pod", klog.KObj(pod))
		return true
	}

	// Case 2: pod that has been assumed could be skipped.
	// An assumed pod can be added again to the scheduling queue if it got an update event
	// during its previous scheduling cycle but before getting assumed.
	isAssumed, err := sched.Cache.IsAssumedPod(pod)
	if err != nil {
		// TODO(91633): pass ctx into a revised HandleError
		utilruntime.HandleError(fmt.Errorf("failed to check whether pod %s/%s is assumed: %v", pod.Namespace, pod.Name, err))
		return false
	}
	return isAssumed
}

// schedulePod tries to schedule the given pod to one of the nodes in the node list.
// If it succeeds, it will return the name of the node.
// If it fails, it will return a FitError with reasons.
func (sched *Scheduler) schedulePod(ctx context.Context, fwk framework.Framework, state *framework.CycleState, pod *v1.Pod) (result ScheduleResult, err error) {
	trace := utiltrace.New("Scheduling", utiltrace.Field{Key: "namespace", Value: pod.Namespace}, utiltrace.Field{Key: "name", Value: pod.Name})
	defer trace.LogIfLong(100 * time.Millisecond)
	// Take a snapshot of the cache's node information.
	var snapshot map[string]*framework.NodeInfo
	if snapshot, err = sched.Cache.UpdateSnapshot(klog.FromContext(ctx)); err != nil {
		return result, err
	}
	trace.Step("Snapshotting scheduler cache and node infos done")

	allNodes := nodeInfoListFromSnapshot(snapshot)
	if len(allNodes) == 0 {
		sched.logger.V(5).Info("Snapshot of nodes is empty")
		return result, ErrNoNodesAvailable
	}

	sched.logger.V(5).Info("Scheduling pod", "pod", pod.Name, "nodes", len(allNodes))

	feasibleNodes, diagnosis, err := sched.findNodesThatFitPod(ctx, fwk, state, pod, snapshot, allNodes)
	if err != nil {
		return result, err
	}
	trace.Step("Computing predicates done")

	if len(feasibleNodes) == 0 {
		sched.logger.V(5).Info("No feasible nodes for pod", "pod", pod.Name)
		return result, &framework.FitError{
			Pod:         pod,
			NumAllNodes: len(allNodes),
			Diagnosis:   diagnosis,
		}
	}

	// When only one node after predicate, just use it.
	if len(feasibleNodes) == 1 {
		sched.logger.V(5).Info("Only one feasible node for pod",
			"pod", pod.Name, "node", feasibleNodes[0].Node().Name)
		return ScheduleResult{
			SuggestedHost:  feasibleNodes[0].Node().Name,
			EvaluatedNodes: 1 + diagnosis.NodeToStatus.Len(),
			FeasibleNodes:  1,
		}, nil
	}

	priorityList, err := prioritizeNodes(ctx, fwk, state, pod, feasibleNodes)
	if err != nil {
		return result, err
	}

	host, _, err := selectHost(priorityList, numberOfHighestScoredNodesToReport)
	trace.Step("Prioritizing done")

	return ScheduleResult{
		SuggestedHost:  host,
		EvaluatedNodes: len(feasibleNodes) + diagnosis.NodeToStatus.Len(),
		FeasibleNodes:  len(feasibleNodes),
	}, err
}

// Filters the nodes to find the ones that fit the pod based on the framework
// filter plugins and filter extenders.
func (sched *Scheduler) findNodesThatFitPod(
	ctx context.Context,
	fwk framework.Framework,
	state *framework.CycleState,
	pod *v1.Pod,
	snapshot map[string]*framework.NodeInfo,
	allNodes []*framework.NodeInfo,
) ([]*framework.NodeInfo, framework.Diagnosis, error) {
	logger := klog.FromContext(ctx)
	diagnosis := framework.Diagnosis{
		NodeToStatus: framework.NewDefaultNodeToStatus(),
	}

	// Run "prefilter" plugins.
	preRes, s, unscheduledPlugins := fwk.RunPreFilterPlugins(ctx, state, pod)
	diagnosis.UnschedulablePlugins = unscheduledPlugins
	if !s.IsSuccess() {
		if !s.IsRejected() {
			return nil, diagnosis, s.AsError()
		}
		// All nodes in NodeToStatus will have the same status so that they can be handled in the preemption.
		diagnosis.NodeToStatus.SetAbsentNodesStatus(s)

		// Record the messages from PreFilter in Diagnosis.PreFilterMsg.
		msg := s.Message()
		diagnosis.PreFilterMsg = msg
		logger.V(5).Info("Status after running PreFilter plugins for pod", "pod", klog.KObj(pod), "status", msg)
		diagnosis.AddPluginStatus(s)
		return nil, diagnosis, nil
	}

	// "NominatedNodeName" can potentially be set in a previous scheduling cycle as a result of preemption.
	// This node is likely the only candidate that will fit the pod, and hence we try it first before iterating over all nodes.
	if len(pod.Status.NominatedNodeName) > 0 {
		feasibleNodes, err := sched.evaluateNominatedNode(ctx, pod, fwk, state, diagnosis, snapshot)
		if err != nil {
			logger.Error(err, "Evaluation failed on nominated node", "pod", klog.KObj(pod), "node", pod.Status.NominatedNodeName)
		}
		// Nominated node passes all the filters, scheduler is good to assign this node to the pod.
		if len(feasibleNodes) != 0 {
			return feasibleNodes, diagnosis, nil
		}
	}

	nodes := allNodes
	if !preRes.AllNodes() {
		nodes = make([]*framework.NodeInfo, 0, len(preRes.NodeNames))
		for nodeName := range preRes.NodeNames {
			// PreRes may return nodeName(s) which do not exist; we verify
			// node exists in the Snapshot.
			if nodeInfo, ok := snapshot[nodeName]; ok {
				nodes = append(nodes, nodeInfo)
			}
		}
		diagnosis.NodeToStatus.SetAbsentNodesStatus(framework.NewStatus(framework.UnschedulableAndUnresolvable, fmt.Sprintf("node(s) didn't satisfy plugin(s) %v", sets.List(unscheduledPlugins))))
	}
	feasibleNodes, err := sched.findNodesThatPassFilters(ctx, fwk, state, pod, &diagnosis, nodes)
	// always try to update the sched.nextStartNodeIndex regardless of whether an error has occurred
	// this is helpful to make sure that all the nodes have a chance to be searched
	processedNodes := len(feasibleNodes) + diagnosis.NodeToStatus.Len()
	sched.nextStartNodeIndex = (sched.nextStartNodeIndex + processedNodes) % len(allNodes)
	if err != nil {
		return nil, diagnosis, err
	}

	return feasibleNodes, diagnosis, nil
}

func (sched *Scheduler) evaluateNominatedNode(
	ctx context.Context,
	pod *v1.Pod,
	fwk framework.Framework,
	state *framework.CycleState,
	diagnosis framework.Diagnosis,
	snapshot map[string]*framework.NodeInfo,
) ([]*framework.NodeInfo, error) {
	nnn := pod.Status.NominatedNodeName
	nodeInfo, ok := snapshot[nnn]
	if !ok {
		return nil, fmt.Errorf("nominated node %q was not found in the current snapshot", nnn)
	}
	node := []*framework.NodeInfo{nodeInfo}
	feasibleNodes, err := sched.findNodesThatPassFilters(ctx, fwk, state, pod, &diagnosis, node)
	if err != nil {
		return nil, err
	}

	return feasibleNodes, nil
}

// hasScoring checks if scoring nodes is configured.
func (sched *Scheduler) hasScoring(fwk framework.Framework) bool {
	if fwk.HasScorePlugins() {
		return true
	}
	return false
}

// findNodesThatPassFilters finds the nodes that fit the filter plugins.
func (sched *Scheduler) findNodesThatPassFilters(
	ctx context.Context,
	fwk framework.Framework,
	state *framework.CycleState,
	pod *v1.Pod,
	diagnosis *framework.Diagnosis,
	nodes []*framework.NodeInfo) ([]*framework.NodeInfo, error) {
	numAllNodes := len(nodes)
	numNodesToFind := sched.numFeasibleNodesToFind(fwk.PercentageOfNodesToScore(), int32(numAllNodes))
	if !sched.hasScoring(fwk) {
		numNodesToFind = 1
	}

	// Create feasible list with enough space to avoid growing it
	// and allow assigning.
	feasibleNodes := make([]*framework.NodeInfo, numNodesToFind)

	if !fwk.HasFilterPlugins() {
		for i := range feasibleNodes {
			feasibleNodes[i] = nodes[(sched.nextStartNodeIndex+i)%numAllNodes]
		}
		return feasibleNodes, nil
	}

	errCh := parallelize.NewErrorChannel()
	var feasibleNodesLen int32
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type nodeStatus struct {
		node   string
		status *framework.Status
	}
	result := make([]*nodeStatus, numAllNodes)
	checkNode := func(i int) {
		// We check the nodes starting from where we left off in the previous scheduling cycle,
		// this is to make sure all nodes have the same chance of being examined across pods.
		nodeInfo := nodes[(sched.nextStartNodeIndex+i)%numAllNodes]
		status := fwk.RunFilterPluginsWithNominatedPods(ctx, state, pod, nodeInfo)
		if status.Code() == framework.Error {
			errCh.SendErrorWithCancel(status.AsError(), cancel)
			return
		}
		if status.IsSuccess() {
			length := atomic.AddInt32(&feasibleNodesLen, 1)
			if length > numNodesToFind {
				cancel()
				atomic.AddInt32(&feasibleNodesLen, -1)
			} else {
				feasibleNodes[length-1] = nodeInfo
			}
		} else {
			result[i] = &nodeStatus{node: nodeInfo.Node().Name, status: status}
		}
	}

	beginCheckNode := time.Now()
	statusCode := framework.Success
	defer func() {
		// We record Filter extension point latency here instead of in framework.go because framework.RunFilterPlugins
		// function is called for each node, whereas we want to have an overall latency for all nodes per scheduling cycle.
		// Note that this latency also includes latency for `addNominatedPods`, which calls framework.RunPreFilterAddPod.
		metrics.FrameworkExtensionPointDuration.WithLabelValues(metrics.Filter, statusCode.String(), fwk.ProfileName()).Observe(metrics.SinceInSeconds(beginCheckNode))
	}()

	// Stops searching for more nodes once the configured number of feasible nodes
	// are found.
	fwk.Parallelizer().Until(ctx, numAllNodes, checkNode, metrics.Filter)
	feasibleNodes = feasibleNodes[:feasibleNodesLen]
	for _, item := range result {
		if item == nil {
			continue
		}
		diagnosis.NodeToStatus.Set(item.node, item.status)
		diagnosis.AddPluginStatus(item.status)
	}
	if err := errCh.ReceiveError(); err != nil {
		statusCode = framework.Error
		return feasibleNodes, err
	}
	return feasibleNodes, nil
}

// numFeasibleNodesToFind returns the number of feasible nodes that once found, the scheduler stops
// its search for more feasible nodes.
func (sched *Scheduler) numFeasibleNodesToFind(percentageOfNodesToScore *int32, numAllNodes int32) (numNodes int32) {
	if numAllNodes < minFeasibleNodesToFind {
		return numAllNodes
	}

	// Use profile percentageOfNodesToScore if it's set. Otherwise, use global percentageOfNodesToScore.
	var percentage int32
	if percentageOfNodesToScore != nil {
		percentage = *percentageOfNodesToScore
	} else {
		percentage = sched.percentageOfNodesToScore
	}

	if percentage == 0 {
		percentage = int32(50) - numAllNodes/125
		if percentage < minFeasibleNodesPercentageToFind {
			percentage = minFeasibleNodesPercentageToFind
		}
	}

	numNodes = numAllNodes * percentage / 100
	if numNodes < minFeasibleNodesToFind {
		return minFeasibleNodesToFind
	}

	return numNodes
}

// prioritizeNodes prioritizes the nodes by running the score plugins,
// which return a score for each node from the call to RunScorePlugins().
// The scores from each plugin are added together to make the score for that node, then
// any extenders are run as well.
// All scores are finally combined (added) to get the total weighted scores of all nodes
func prioritizeNodes(
	ctx context.Context,
	fwk framework.Framework,
	state *framework.CycleState,
	pod *v1.Pod,
	nodes []*framework.NodeInfo,
) ([]framework.NodePluginScores, error) {
	logger := klog.FromContext(ctx)
	// If no priority configs are provided, then all nodes will have a score of one.
	// This is required to generate the priority list in the required format
	if !fwk.HasScorePlugins() {
		result := make([]framework.NodePluginScores, 0, len(nodes))
		for i := range nodes {
			result = append(result, framework.NodePluginScores{
				Name:       nodes[i].Node().Name,
				TotalScore: 1,
			})
		}
		return result, nil
	}

	// Run PreScore plugins.
	preScoreStatus := fwk.RunPreScorePlugins(ctx, state, pod, nodes)
	if !preScoreStatus.IsSuccess() {
		return nil, preScoreStatus.AsError()
	}

	// Run the Score plugins.
	nodesScores, scoreStatus := fwk.RunScorePlugins(ctx, state, pod, nodes)
	if !scoreStatus.IsSuccess() {
		return nil, scoreStatus.AsError()
	}

	// Additional details logged at level 10 if enabled.
	loggerVTen := logger.V(10)
	if loggerVTen.Enabled() {
		for _, nodeScore := range nodesScores {
			for _, pluginScore := range nodeScore.Scores {
				loggerVTen.Info("Plugin scored node for pod", "pod", klog.KObj(pod), "plugin", pluginScore.Name, "node", nodeScore.Name, "score", pluginScore.Score)
			}
		}
	}

	if loggerVTen.Enabled() {
		for i := range nodesScores {
			loggerVTen.Info("Calculated node's final score for pod", "pod", klog.KObj(pod), "node", nodesScores[i].Name, "score", nodesScores[i].TotalScore)
		}
	}
	return nodesScores, nil
}

var errEmptyPriorityList = errors.New("empty priorityList")

// selectHost takes a prioritized list of nodes and then picks one
// in a reservoir sampling manner from the nodes that had the highest score.
// It also returns the top {count} Nodes,
// and the top of the list will be always the selected host.
func selectHost(nodeScoreList []framework.NodePluginScores, count int) (string, []framework.NodePluginScores, error) {
	if len(nodeScoreList) == 0 {
		return "", nil, errEmptyPriorityList
	}

	var h nodeScoreHeap = nodeScoreList
	heap.Init(&h)
	cntOfMaxScore := 1
	selectedIndex := 0
	// The top of the heap is the NodeScoreResult with the highest score.
	sortedNodeScoreList := make([]framework.NodePluginScores, 0, count)
	sortedNodeScoreList = append(sortedNodeScoreList, heap.Pop(&h).(framework.NodePluginScores))

	// This for-loop will continue until all Nodes with the highest scores get checked for a reservoir sampling,
	// and sortedNodeScoreList gets (count - 1) elements.
	for ns := heap.Pop(&h).(framework.NodePluginScores); ; ns = heap.Pop(&h).(framework.NodePluginScores) {
		if ns.TotalScore != sortedNodeScoreList[0].TotalScore && len(sortedNodeScoreList) == count {
			break
		}

		if ns.TotalScore == sortedNodeScoreList[0].TotalScore {
			cntOfMaxScore++
			if rand.Intn(cntOfMaxScore) == 0 {
				// Replace the candidate with probability of 1/cntOfMaxScore
				selectedIndex = cntOfMaxScore - 1
			}
		}

		sortedNodeScoreList = append(sortedNodeScoreList, ns)

		if h.Len() == 0 {
			break
		}
	}

	if selectedIndex != 0 {
		// replace the first one with selected one
		previous := sortedNodeScoreList[0]
		sortedNodeScoreList[0] = sortedNodeScoreList[selectedIndex]
		sortedNodeScoreList[selectedIndex] = previous
	}

	if len(sortedNodeScoreList) > count {
		sortedNodeScoreList = sortedNodeScoreList[:count]
	}

	return sortedNodeScoreList[0].Name, sortedNodeScoreList, nil
}

// nodeScoreHeap is a heap of framework.NodePluginScores.
type nodeScoreHeap []framework.NodePluginScores

// nodeScoreHeap implements heap.Interface.
var _ heap.Interface = &nodeScoreHeap{}

func (h nodeScoreHeap) Len() int           { return len(h) }
func (h nodeScoreHeap) Less(i, j int) bool { return h[i].TotalScore > h[j].TotalScore }
func (h nodeScoreHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *nodeScoreHeap) Push(x interface{}) {
	*h = append(*h, x.(framework.NodePluginScores))
}

func (h *nodeScoreHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

func nodeInfoListFromSnapshot(snapshot map[string]*framework.NodeInfo) []*framework.NodeInfo {
	nodeNames := make([]string, 0, len(snapshot))
	for nodeName, nodeInfo := range snapshot {
		if nodeInfo == nil || nodeInfo.Node() == nil {
			continue
		}
		nodeNames = append(nodeNames, nodeName)
	}
	sort.Strings(nodeNames)

	nodes := make([]*framework.NodeInfo, 0, len(nodeNames))
	for _, nodeName := range nodeNames {
		nodes = append(nodes, snapshot[nodeName])
	}
	return nodes
}

// assume signals to the cache that a pod is already in the cache, so that binding can be asynchronous.
// assume modifies `assumed`.
func (sched *Scheduler) assume(logger klog.Logger, assumed *v1.Pod, host string) error {
	// Optimistically assume that the binding will succeed and send it to apiserver
	// in the background.
	// If the binding fails, scheduler will release resources allocated to assumed pod
	// immediately.
	assumed.Spec.NodeName = host

	if err := sched.Cache.AssumePod(logger, assumed); err != nil {
		logger.Error(err, "Scheduler cache AssumePod failed")
		return err
	}
	// if "assumed" is a nominated pod, we should remove it from internal cache
	if sched.SchedulingQueue != nil {
		sched.SchedulingQueue.DeleteNominatedPodIfExists(assumed)
	}

	return nil
}

// handleSchedulingFailure records an event for the pod that indicates the
// pod has failed to schedule. Also, update the pod condition and nominated node name if set.
func (sched *Scheduler) handleSchedulingFailure(ctx context.Context, fwk framework.Framework, podInfo *framework.QueuedPodInfo, status *framework.Status, nominatingInfo *framework.NominatingInfo, start time.Time) {
	calledDone := false
	defer func() {
		if !calledDone {
			// Basically, AddUnschedulableIfNotPresent calls DonePod internally.
			// But, AddUnschedulableIfNotPresent isn't called in some corner cases.
			// Here, we call DonePod explicitly to avoid leaking the pod.
			sched.SchedulingQueue.Done(podInfo.Pod.UID)
		}
	}()

	logger := klog.FromContext(ctx)
	reason := v1.PodReasonSchedulerError
	if status.IsRejected() {
		reason = v1.PodReasonUnschedulable
	}

	switch reason {
	case v1.PodReasonUnschedulable:
		metrics.PodUnschedulable(fwk.ProfileName(), metrics.SinceInSeconds(start))
	case v1.PodReasonSchedulerError:
		metrics.PodScheduleError(fwk.ProfileName(), metrics.SinceInSeconds(start))
	}

	pod := podInfo.Pod
	err := status.AsError()
	errMsg := status.Message()

	if err == ErrNoNodesAvailable {
		logger.V(2).Info("Unable to schedule pod; no nodes are registered to the cluster; waiting", "pod", klog.KObj(pod))
	} else if fitError, ok := err.(*framework.FitError); ok { // Inject UnschedulablePlugins to PodInfo, which will be used later for moving Pods between queues efficiently.
		podInfo.UnschedulablePlugins = fitError.Diagnosis.UnschedulablePlugins
		podInfo.PendingPlugins = fitError.Diagnosis.PendingPlugins
		logger.V(2).Info("Unable to schedule pod; no fit; waiting", "pod", klog.KObj(pod), "err", errMsg)
	} else {
		logger.Error(err, "Error scheduling pod; retrying", "pod", klog.KObj(pod))
	}

	// Check if the Pod exists in informer cache. In the Lambda scheduler we may not
	// have a SharedInformerFactory, so fall back to a direct API lookup.
	cachedPod, e := sched.getPodForSchedulingFailure(ctx, fwk, pod)
	if e != nil {
		logger.Info("Pod doesn't exist in informer cache", "pod", klog.KObj(pod), "err", e)
		// We need to call DonePod here because we don't call AddUnschedulableIfNotPresent in this case.
	} else {
		// In the case of extender, the pod may have been bound successfully, but timed out returning its response to the scheduler.
		// It could result in the live version to carry .spec.nodeName, and that's inconsistent with the internal-queued version.
		if len(cachedPod.Spec.NodeName) != 0 {
			logger.Info("Pod has been assigned to node. Abort adding it back to queue.", "pod", klog.KObj(pod), "node", cachedPod.Spec.NodeName)
			// We need to call DonePod here because we don't call AddUnschedulableIfNotPresent in this case.
		} else {
			// As <cachedPod> is from SharedInformer, we need to do a DeepCopy() here.
			// ignore this err since apiserver doesn't properly validate affinity terms
			// and we can't fix the validation for backwards compatibility.
			podInfo.PodInfo, _ = framework.NewPodInfo(cachedPod.DeepCopy())
			if err := sched.SchedulingQueue.AddUnschedulableIfNotPresent(logger, podInfo, sched.SchedulingQueue.SchedulingCycle()); err != nil {
				logger.Error(err, "Error occurred")
			}
			calledDone = true
		}
	}

	// Update the scheduling queue with the nominated pod information. Without
	// this, there would be a race condition between the next scheduling cycle
	// and the time the scheduler receives a Pod Update for the nominated pod.
	// Here we check for nil only for tests.
	if sched.SchedulingQueue != nil {
		sched.SchedulingQueue.AddNominatedPod(logger, podInfo.PodInfo, nominatingInfo)
	}

	if err == nil {
		// Only tests can reach here.
		return
	}

	msg := truncateMessage(errMsg)
	fwk.EventRecorder().Eventf(pod, nil, v1.EventTypeWarning, "FailedScheduling", "Scheduling", msg)
	if err := updatePod(ctx, sched.client, pod, &v1.PodCondition{
		Type:               v1.PodScheduled,
		ObservedGeneration: podutil.GetPodObservedGenerationIfEnabledOnCondition(&pod.Status, pod.Generation, v1.PodScheduled),
		Status:             v1.ConditionFalse,
		Reason:             reason,
		Message:            errMsg,
	}, nominatingInfo); err != nil {
		logger.Error(err, "Error updating pod", "pod", klog.KObj(pod))
	}
}

func (sched *Scheduler) getPodForSchedulingFailure(ctx context.Context, fwk framework.Framework, pod *v1.Pod) (*v1.Pod, error) {
	if fwk != nil && fwk.SharedInformerFactory() != nil {
		podLister := fwk.SharedInformerFactory().Core().V1().Pods().Lister()
		return podLister.Pods(pod.Namespace).Get(pod.Name)
	}

	if sched.client == nil {
		return nil, fmt.Errorf("scheduler client is not configured")
	}

	klog.FromContext(ctx).V(4).Info("Shared informer factory is unavailable; falling back to direct pod lookup", "pod", klog.KObj(pod))
	return sched.client.CoreV1().Pods(pod.Namespace).Get(ctx, pod.Name, metav1.GetOptions{})
}

// truncateMessage truncates a message if it hits the NoteLengthLimit.
func truncateMessage(message string) string {
	max := validation.NoteLengthLimit
	if len(message) <= max {
		return message
	}
	suffix := " ..."
	return message[:max-len(suffix)] + suffix
}

func updatePod(ctx context.Context, client clientset.Interface, pod *v1.Pod, condition *v1.PodCondition, nominatingInfo *framework.NominatingInfo) error {
	logger := klog.FromContext(ctx)
	logger.V(3).Info("Updating pod condition", "pod", klog.KObj(pod), "conditionType", condition.Type, "conditionStatus", condition.Status, "conditionReason", condition.Reason)
	podStatusCopy := pod.Status.DeepCopy()
	// NominatedNodeName is updated only if we are trying to set it, and the value is
	// different from the existing one.
	nnnNeedsUpdate := nominatingInfo.Mode() == framework.ModeOverride && pod.Status.NominatedNodeName != nominatingInfo.NominatedNodeName
	if !podutil.UpdatePodCondition(podStatusCopy, condition) && !nnnNeedsUpdate {
		return nil
	}
	if nnnNeedsUpdate {
		podStatusCopy.NominatedNodeName = nominatingInfo.NominatedNodeName
	}
	return util.PatchPodStatus(ctx, client, pod, podStatusCopy)
}
