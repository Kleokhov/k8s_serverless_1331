package scheduler

import (
	"context"
	"fmt"
	"math/rand"
	"strconv"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/scheduler/framework"
	"k8s.io/kubernetes/pkg/scheduler/metrics"
)

// CompleteBinding rebuilds the binding-cycle state for a scheduled pod and finishes the bind.
func (sched *Scheduler) CompleteBinding(ctx context.Context, req BindingRequest) error {
	if req.Pod == nil {
		return fmt.Errorf("binding request pod is required")
	}

	podInfo, err := req.QueuedPodInfo()
	if err != nil {
		return err
	}

	logger := klog.FromContext(ctx)
	logger = klog.LoggerWithValues(logger, "pod", klog.KObj(podInfo.Pod))
	ctx = klog.NewContext(ctx, logger)

	fwk, err := sched.frameworkForPod(podInfo.Pod)
	if err != nil {
		return err
	}

	start := req.StartTime
	if start.IsZero() {
		start = time.Now()
	}

	features := sched.featuresForPod(podInfo.Pod)
	scheduleResult := req.ScheduleResult()
	if features.simpleBindingPath() {
		status := sched.bindingCycleFast(ctx, fwk, scheduleResult, podInfo, start)
		if !status.IsSuccess() {
			sched.handleBindingCycleError(ctx, nil, fwk, podInfo, start, scheduleResult, status, false)
		}
		return nil
	}

	state := framework.NewCycleState()
	state.SetRecordPluginMetrics(rand.Intn(100) < pluginMetricsSamplePercent)

	var podsToActivate *framework.PodsToActivate
	if features.needsPodsToActivate() {
		podsToActivate = framework.NewPodsToActivate()
		state.Write(framework.PodsToActivateKey, podsToActivate)
	}

	status, reserved := sched.bindingCycle(ctx, state, fwk, scheduleResult, podInfo, start, podsToActivate)
	if !status.IsSuccess() {
		sched.handleBindingCycleError(ctx, state, fwk, podInfo, start, scheduleResult, status, reserved)
	}

	return nil
}

// bindingCycle tries to bind an assumed Pod.
func (sched *Scheduler) bindingCycle(
	ctx context.Context,
	state *framework.CycleState,
	fwk framework.Framework,
	scheduleResult ScheduleResult,
	assumedPodInfo *framework.QueuedPodInfo,
	start time.Time,
	podsToActivate *framework.PodsToActivate,
) (*framework.Status, bool) {
	logger := klog.FromContext(ctx)
	assumedPod := assumedPodInfo.Pod

	status, reserved := sched.prepareBindingCycle(ctx, state, fwk, assumedPod, scheduleResult.SuggestedHost)
	if !status.IsSuccess() {
		return status, reserved
	}

	// Run "permit" plugins.
	if status := fwk.WaitOnPermit(ctx, assumedPod); !status.IsSuccess() {
		if status.IsRejected() {
			return bindingRejectedStatus(assumedPodInfo.Pod, scheduleResult.SuggestedHost, status), reserved
		}
		return status, reserved
	}

	// Any failures after this point cannot lead to the Pod being considered unschedulable.
	// We define the Pod as "unschedulable" only when Pods are rejected at specific extension points,
	// and Permit is the last one in the scheduling/binding cycle.
	sched.SchedulingQueue.Done(assumedPod.UID)

	// Run "prebind" plugins.
	if status := fwk.RunPreBindPlugins(ctx, state, assumedPod, scheduleResult.SuggestedHost); !status.IsSuccess() {
		return status, reserved
	}

	// Run "bind" plugins.
	if status := sched.bind(ctx, fwk, assumedPod, scheduleResult.SuggestedHost, state); !status.IsSuccess() {
		return status, reserved
	}

	logger.V(2).Info("Successfully bound pod to node", "pod", klog.KObj(assumedPod), "node", scheduleResult.SuggestedHost, "evaluatedNodes", scheduleResult.EvaluatedNodes, "feasibleNodes", scheduleResult.FeasibleNodes)
	metrics.PodScheduled(fwk.ProfileName(), metrics.SinceInSeconds(start))
	metrics.PodSchedulingAttempts.Observe(float64(assumedPodInfo.Attempts))
	if assumedPodInfo.InitialAttemptTimestamp != nil {
		metrics.PodSchedulingSLIDuration.WithLabelValues(getAttemptsLabel(assumedPodInfo)).Observe(metrics.SinceInSeconds(*assumedPodInfo.InitialAttemptTimestamp))
	}

	// Run "postbind" plugins.
	fwk.RunPostBindPlugins(ctx, state, assumedPod, scheduleResult.SuggestedHost)

	// At the end of a successful binding cycle, move up Pods if needed.
	if podsToActivate != nil && len(podsToActivate.Map) != 0 {
		sched.SchedulingQueue.Activate(logger, podsToActivate.Map)
	}

	return nil, reserved
}

func (sched *Scheduler) bindingCycleFast(
	ctx context.Context,
	fwk framework.Framework,
	scheduleResult ScheduleResult,
	assumedPodInfo *framework.QueuedPodInfo,
	start time.Time,
) *framework.Status {
	logger := klog.FromContext(ctx)
	assumedPod := assumedPodInfo.Pod

	if status := sched.ensureBindingTarget(ctx, assumedPod, scheduleResult.SuggestedHost); !status.IsSuccess() {
		return status
	}

	sched.SchedulingQueue.Done(assumedPod.UID)

	if status := sched.bindFast(ctx, fwk, assumedPod, scheduleResult.SuggestedHost); !status.IsSuccess() {
		return status
	}

	logger.V(2).Info("Successfully bound pod to node", "pod", klog.KObj(assumedPod),
		"node", scheduleResult.SuggestedHost, "evaluatedNodes", scheduleResult.EvaluatedNodes, "feasibleNodes", scheduleResult.FeasibleNodes)
	metrics.PodScheduled(fwk.ProfileName(), metrics.SinceInSeconds(start))
	metrics.PodSchedulingAttempts.Observe(float64(assumedPodInfo.Attempts))
	if assumedPodInfo.InitialAttemptTimestamp != nil {
		metrics.PodSchedulingSLIDuration.WithLabelValues(getAttemptsLabel(assumedPodInfo)).Observe(metrics.SinceInSeconds(*assumedPodInfo.InitialAttemptTimestamp))
	}

	return nil
}

func (sched *Scheduler) prepareBindingCycle(
	ctx context.Context,
	state *framework.CycleState,
	fwk framework.Framework,
	pod *v1.Pod,
	targetNode string,
) (*framework.Status, bool) {
	nodeInfo, status := sched.bindingNodeInfo(ctx, pod, targetNode)
	if !status.IsSuccess() {
		return status, false
	}

	preRes, status, _ := fwk.RunPreFilterPlugins(ctx, state, pod)
	if !status.IsSuccess() {
		if !status.IsRejected() {
			return status, false
		}
		rejected := bindingRejectedStatus(pod, targetNode, status)
		if fitErr, ok := rejected.AsError().(*framework.FitError); ok {
			fitErr.Diagnosis.PreFilterMsg = status.Message()
		}
		return rejected, false
	}

	if !preRes.AllNodes() && (preRes.NodeNames == nil || !preRes.NodeNames.Has(targetNode)) {
		status := framework.NewStatus(framework.UnschedulableAndUnresolvable, fmt.Sprintf("node %q didn't satisfy prefilter results", targetNode))
		return bindingRejectedStatus(pod, targetNode, status), false
	}

	filterStatus := fwk.RunFilterPluginsWithNominatedPods(ctx, state, pod, nodeInfo)
	if filterStatus.Code() == framework.Error {
		return filterStatus, false
	}
	if !filterStatus.IsSuccess() {
		return bindingRejectedStatus(pod, targetNode, filterStatus), false
	}

	// Reserve plugins may need to clean up even if one of them fails midway through the chain.
	reserved := true
	if status := fwk.RunReservePluginsReserve(ctx, state, pod, targetNode); !status.IsSuccess() {
		if status.IsRejected() {
			return bindingRejectedStatus(pod, targetNode, status), reserved
		}
		return status, reserved
	}

	runPermitStatus := fwk.RunPermitPlugins(ctx, state, pod, targetNode)
	if !runPermitStatus.IsWait() && !runPermitStatus.IsSuccess() {
		if runPermitStatus.IsRejected() {
			return bindingRejectedStatus(pod, targetNode, runPermitStatus), reserved
		}
		return runPermitStatus, reserved
	}

	return nil, reserved
}

func (sched *Scheduler) ensureBindingTarget(ctx context.Context, pod *v1.Pod, targetNode string) *framework.Status {
	_, status := sched.bindingNodeInfo(ctx, pod, targetNode)
	return status
}

func (sched *Scheduler) bindingNodeInfo(ctx context.Context, pod *v1.Pod, targetNode string) (*framework.NodeInfo, *framework.Status) {
	logger := klog.FromContext(ctx)
	snapshot, err := sched.Cache.UpdateSnapshot(logger)
	if err != nil {
		return nil, framework.AsStatus(err)
	}

	nodeInfo, ok := snapshot[targetNode]
	if !ok || nodeInfo == nil || nodeInfo.Node() == nil {
		status := framework.NewStatus(framework.UnschedulableAndUnresolvable, fmt.Sprintf("node %q was not found in the current snapshot", targetNode))
		return nil, bindingRejectedStatus(pod, targetNode, status)
	}

	return nodeInfo, nil
}

func (sched *Scheduler) handleBindingDispatchError(
	ctx context.Context,
	fwk framework.Framework,
	podInfo *framework.QueuedPodInfo,
	start time.Time,
	err error,
) {
	logger := klog.FromContext(ctx)
	assumedPod := podInfo.Pod

	if forgetErr := sched.Cache.ForgetPod(logger, assumedPod); forgetErr != nil {
		logger.Error(forgetErr, "scheduler cache ForgetPod failed")
	} else {
		sched.SchedulingQueue.MoveAllToActiveOrBackoffQueue(logger, framework.EventAssignedPodDelete, assumedPod, nil, nil)
	}

	sched.FailureHandler(ctx, fwk, podInfo, framework.AsStatus(fmt.Errorf("dispatching binding request: %w", err)), clearNominatedNode, start)
}

func (sched *Scheduler) handleBindingCycleError(
	ctx context.Context,
	state *framework.CycleState,
	fwk framework.Framework,
	podInfo *framework.QueuedPodInfo,
	start time.Time,
	scheduleResult ScheduleResult,
	status *framework.Status,
	reserved bool,
) {
	logger := klog.FromContext(ctx)
	assumedPod := podInfo.Pod

	// Trigger un-reserve plugins to clean up state associated with the reserved Pod.
	if reserved {
		fwk.RunReservePluginsUnreserve(ctx, state, assumedPod, scheduleResult.SuggestedHost)
	}
	if forgetErr := sched.Cache.ForgetPod(logger, assumedPod); forgetErr != nil {
		logger.Error(forgetErr, "scheduler cache ForgetPod failed")
	} else {
		// "Forget"ing an assumed Pod in binding cycle should be treated as a PodDelete event,
		// as the assumed Pod had occupied a certain amount of resources in scheduler cache.
		if status.IsRejected() {
			defer sched.SchedulingQueue.MoveAllToActiveOrBackoffQueue(logger, framework.EventAssignedPodDelete, assumedPod, nil, func(pod *v1.Pod) bool {
				return assumedPod.UID != pod.UID
			})
		} else {
			sched.SchedulingQueue.MoveAllToActiveOrBackoffQueue(logger, framework.EventAssignedPodDelete, assumedPod, nil, nil)
		}
	}

	sched.FailureHandler(ctx, fwk, podInfo, status, clearNominatedNode, start)
}

// bind binds a pod to a given node defined in a binding object.
func (sched *Scheduler) bind(ctx context.Context, fwk framework.Framework, assumed *v1.Pod, targetNode string, state *framework.CycleState) (status *framework.Status) {
	logger := klog.FromContext(ctx)
	defer func() {
		sched.finishBinding(logger, fwk, assumed, targetNode, status)
	}()

	return fwk.RunBindPlugins(ctx, state, assumed, targetNode)
}

func (sched *Scheduler) bindFast(ctx context.Context, fwk framework.Framework, assumed *v1.Pod, targetNode string) (status *framework.Status) {
	logger := klog.FromContext(ctx)
	defer func() {
		sched.finishBinding(logger, fwk, assumed, targetNode, status)
	}()

	binding := &v1.Binding{
		ObjectMeta: metav1.ObjectMeta{Namespace: assumed.Namespace, Name: assumed.Name, UID: assumed.UID},
		Target:     v1.ObjectReference{Kind: "Node", Name: targetNode},
	}
	if err := sched.client.CoreV1().Pods(binding.Namespace).Bind(ctx, binding, metav1.CreateOptions{}); err != nil {
		return framework.AsStatus(err)
	}
	return nil
}

func (sched *Scheduler) finishBinding(logger klog.Logger, fwk framework.Framework, assumed *v1.Pod, targetNode string, status *framework.Status) {
	if finErr := sched.Cache.FinishBinding(logger, assumed); finErr != nil {
		logger.Error(finErr, "Scheduler cache FinishBinding failed")
	}
	if !status.IsSuccess() {
		logger.V(1).Info("Failed to bind pod", "pod", klog.KObj(assumed))
		return
	}

	fwk.EventRecorder().Eventf(assumed, nil, v1.EventTypeNormal, "Scheduled", "Binding", "Successfully assigned %v/%v to %v", assumed.Namespace, assumed.Name, targetNode)
}

func bindingRejectedStatus(pod *v1.Pod, targetNode string, status *framework.Status) *framework.Status {
	if status == nil || !status.IsRejected() {
		return status
	}

	fitErr := &framework.FitError{
		NumAllNodes: 1,
		Pod:         pod,
		Diagnosis: framework.Diagnosis{
			NodeToStatus: framework.NewDefaultNodeToStatus(),
		},
	}
	fitErr.Diagnosis.NodeToStatus.Set(targetNode, status)
	fitErr.Diagnosis.AddPluginStatus(status)
	return framework.NewStatus(status.Code()).WithError(fitErr)
}

func getAttemptsLabel(p *framework.QueuedPodInfo) string {
	// We breakdown the pod scheduling duration by attempts capped to a limit
	// to avoid ending up with a high cardinality metric.
	if p.Attempts >= 15 {
		return "15+"
	}
	return strconv.Itoa(p.Attempts)
}
