/*
Copyright 2017 The Kubernetes Authors.

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

// This file contains structures that implement scheduling queue types.
// Scheduling queues hold pods waiting to be scheduled. This file implements a
// priority queue which has two sub queues and a additional data structure,
// namely: activeQ, backoffQ and unschedulablePods.
// - activeQ holds pods that are being considered for scheduling.
// - backoffQ holds pods that moved from unschedulablePods and will move to
//   activeQ when their backoff periods complete.
// - unschedulablePods holds pods that were already attempted for scheduling and
//   are currently determined to be unschedulable.

package queue

import (
	"context"
	"fmt"
	"lambda/pkg/scheduler/backend/awsstore"
	"reflect"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/scheduler/framework"
	"k8s.io/kubernetes/pkg/scheduler/framework/plugins/podtopologyspread"
	"k8s.io/kubernetes/pkg/scheduler/metrics"
	"k8s.io/utils/clock"
)

const (
	// DefaultPodMaxInUnschedulablePodsDuration is the default value for the maximum
	// time a pod can stay in unschedulablePods. If a pod stays in unschedulablePods
	// for longer than this value, the pod will be moved from unschedulablePods to
	// backoffQ or activeQ. If this value is empty, the default value (5min)
	// will be used.
	DefaultPodMaxInUnschedulablePodsDuration time.Duration = 5 * time.Minute
	// Scheduling queue names
	activeQ           = "Active"
	backoffQ          = "Backoff"
	unschedulablePods = "Unschedulable"

	preEnqueue = "PreEnqueue"
)

const (
	// DefaultPodInitialBackoffDuration is the default value for the initial backoff duration
	// for unschedulable pods. To change the default podInitialBackoffDurationSeconds used by the
	// scheduler, update the ComponentConfig value in defaults.go
	DefaultPodInitialBackoffDuration time.Duration = 1 * time.Second
	// DefaultPodMaxBackoffDuration is the default value for the max backoff duration
	// for unschedulable pods. To change the default podMaxBackoffDurationSeconds used by the
	// scheduler, update the ComponentConfig value in defaults.go
	DefaultPodMaxBackoffDuration time.Duration = 10 * time.Second
)

// PreEnqueueCheck is a function type. It's used to build functions that
// run against a Pod and the caller can choose to enqueue or skip the Pod
// by the checking result.
type PreEnqueueCheck func(pod *v1.Pod) bool

// SchedulingQueue is an interface for a queue to store pods waiting to be scheduled.
// The interface follows a pattern similar to cache.FIFO and cache.Heap and
// makes it easy to use those data structures as a SchedulingQueue.
type SchedulingQueue interface {
	framework.PodNominator
	Add(logger klog.Logger, pod *v1.Pod)
	// Activate moves the given pods to activeQ.
	// If a pod isn't found in unschedulablePods or backoffQ and it's in-flight,
	// the wildcard event is registered so that the pod will be requeued when it comes back.
	// But, if a pod isn't found in unschedulablePods or backoffQ and it's not in-flight (i.e., completely unknown pod),
	// Activate would ignore the pod.
	Activate(logger klog.Logger, pods map[string]*v1.Pod)
	// AddUnschedulableIfNotPresent adds an unschedulable pod back to scheduling queue.
	// The podSchedulingCycle represents the current scheduling cycle number which can be
	// returned by calling SchedulingCycle().
	AddUnschedulableIfNotPresent(logger klog.Logger, pod *framework.QueuedPodInfo, podSchedulingCycle int64) error
	// SchedulingCycle returns the current number of scheduling cycle which is
	// cached by scheduling queue. Normally, incrementing this number whenever
	// a pod is popped (e.g. called Pop()) is enough.
	SchedulingCycle() int64
	// Pop removes the head of the queue and returns it. It blocks if the
	// queue is empty and waits until a new item is added to the queue.
	Pop(logger klog.Logger) (*framework.QueuedPodInfo, error)
	// Done must be called for pod returned by Pop. This allows the queue to
	// keep track of which pods are currently being processed.
	Done(types.UID)
	Update(logger klog.Logger, oldPod, newPod *v1.Pod)
	Delete(pod *v1.Pod)
	// Important Note: preCheck shouldn't include anything that depends on the in-tree plugins' logic.
	// (e.g., filter Pods based on added/updated Node's capacity, etc.)
	// We know currently some do, but we'll eventually remove them in favor of the scheduling queue hint.
	MoveAllToActiveOrBackoffQueue(logger klog.Logger, event framework.ClusterEvent, oldObj, newObj interface{}, preCheck PreEnqueueCheck)
	AssignedPodAdded(logger klog.Logger, pod *v1.Pod)
	AssignedPodUpdated(logger klog.Logger, oldPod, newPod *v1.Pod, event framework.ClusterEvent)

	// Close closes the SchedulingQueue so that the goroutine which is
	// waiting to pop items can exit gracefully.
	Close()
	// Run starts the goroutines managing the queue.
	Run(logger klog.Logger)

	// The following functions are supposed to be used only for testing or debugging.
	GetPod(name, namespace string) (*framework.QueuedPodInfo, bool)
	PendingPods() ([]*v1.Pod, string)
	PodsInActiveQ() []*v1.Pod
	// PodsInBackoffQ returns all the Pods in the backoffQ.
	PodsInBackoffQ() []*v1.Pod
	UnschedulablePods() []*v1.Pod

	FlushBackoffQCompletedOnce(logger klog.Logger) int
	FlushUnschedulablePodsLeftoverOnce(logger klog.Logger) int
}

// NewSchedulingQueue initializes a priority queue as a new scheduling queue.
func NewSchedulingQueue(
	ctx context.Context,
	opts ...Option,
) (SchedulingQueue, error) {
	return NewPriorityQueue(ctx, opts...)
}

// PriorityQueue implements a scheduling queue.
// The head of PriorityQueue is the highest priority pending pod. This structure
// has two sub queues and a additional data structure, namely: activeQ,
// backoffQ and unschedulablePods.
//   - activeQ holds pods that are being considered for scheduling.
//   - backoffQ holds pods that moved from unschedulablePods and will move to
//     activeQ when their backoff periods complete.
//   - unschedulablePods holds pods that were already attempted for scheduling and
//     are currently determined to be unschedulable.
type PriorityQueue struct {
	*nominator

	stop  chan struct{}
	clock clock.WithTicker

	// lock takes precedence and should be taken first,
	// before any other locks in the queue (activeQueue.lock or backoffQueue.lock or nominator.nLock).
	// Correct locking order is: lock > activeQueue.lock > backoffQueue.lock > nominator.nLock.
	lock sync.RWMutex

	// the maximum time a pod can stay in the unschedulablePods.
	podMaxInUnschedulablePodsDuration time.Duration

	activeQ  activeQueuer
	backoffQ backoffQueuer
	// unschedulablePods holds pods that have been tried and determined unschedulable.
	unschedulablePods *UnschedulablePods
	// moveRequestCycle caches the sequence number of scheduling cycle when we
	// received a move request. Unschedulable pods in and before this scheduling
	// cycle will be put back to activeQueue if we were trying to schedule them
	// when we received move request.
	// TODO: this will be removed after SchedulingQueueHint goes to stable and the feature gate is removed.
	moveRequestCycle int64
}

type priorityQueueOptions struct {
	clock                             clock.WithTicker
	podInitialBackoffDuration         time.Duration
	podMaxBackoffDuration             time.Duration
	podMaxInUnschedulablePodsDuration time.Duration

	kubeClient kubernetes.Interface

	awsCfg         *aws.Config
	ddbOpts        []func(*dynamodb.Options)
	getBackoffTime awsstore.BackoffTimeFunc

	createActiveQueue       bool
	createBackoffQueues     bool
	createNominator         bool
	createUnschedulablePods bool

	activeTableName   string
	backoffTableName  string
	miscMapTableName  string

	awsActiveQ        *awsstore.ActiveQueueAWS
	awsBackoffQ       *awsstore.BackoffQueuesAWS
	nominator         *nominator
	unschedulablePods *UnschedulablePods
}

// Option configures a PriorityQueue
type Option func(*priorityQueueOptions)

// WithClock sets clock for PriorityQueue, the default clock is clock.RealClock.
func WithClock(clock clock.WithTicker) Option {
	return func(o *priorityQueueOptions) {
		o.clock = clock
	}
}

// WithPodInitialBackoffDuration sets pod initial backoff duration for PriorityQueue.
func WithPodInitialBackoffDuration(duration time.Duration) Option {
	return func(o *priorityQueueOptions) {
		o.podInitialBackoffDuration = duration
	}
}

// WithPodMaxBackoffDuration sets pod max backoff duration for PriorityQueue.
func WithPodMaxBackoffDuration(duration time.Duration) Option {
	return func(o *priorityQueueOptions) {
		o.podMaxBackoffDuration = duration
	}
}

// WithPodMaxInUnschedulablePodsDuration sets podMaxInUnschedulablePodsDuration for PriorityQueue.
func WithPodMaxInUnschedulablePodsDuration(duration time.Duration) Option {
	return func(o *priorityQueueOptions) {
		o.podMaxInUnschedulablePodsDuration = duration
	}
}

func WithAWSQueues(active *awsstore.ActiveQueueAWS, backoff *awsstore.BackoffQueuesAWS) Option {
	return func(o *priorityQueueOptions) {
		o.awsActiveQ = active
		o.awsBackoffQ = backoff
	}
}

func WithNominator(n *nominator) Option {
	return func(o *priorityQueueOptions) {
		o.nominator = n
	}
}

func WithUnschedulablePods(u *UnschedulablePods) Option {
	return func(o *priorityQueueOptions) {
		o.unschedulablePods = u
	}
}

func WithKubeClient(client kubernetes.Interface) Option {
	return func(o *priorityQueueOptions) {
		o.kubeClient = client
	}
}

var defaultPriorityQueueOptions = priorityQueueOptions{
	clock:                             clock.RealClock{},
	podInitialBackoffDuration:         DefaultPodInitialBackoffDuration,
	podMaxBackoffDuration:             DefaultPodMaxBackoffDuration,
	podMaxInUnschedulablePodsDuration: DefaultPodMaxInUnschedulablePodsDuration,
}

type queueTransitionResult int

const (
	queueTransitionSkipped queueTransitionResult = iota
	queueTransitionMoved
	queueTransitionWriteFailed
)

// Making sure that PriorityQueue implements SchedulingQueue.
var _ SchedulingQueue = &PriorityQueue{}

// newQueuedPodInfoForLookup builds a QueuedPodInfo object for a lookup in the queue.
func newQueuedPodInfoForLookup(pod *v1.Pod, plugins ...string) *framework.QueuedPodInfo {
	// Since this is only used for a lookup in the queue, we only need to set the Pod,
	// and so we avoid creating a full PodInfo, which is expensive to instantiate frequently.
	return &framework.QueuedPodInfo{
		PodInfo:              &framework.PodInfo{Pod: pod},
		UnschedulablePlugins: sets.New(plugins...),
	}
}

// NewPriorityQueue creates a PriorityQueue object.
func NewPriorityQueue(
	ctx context.Context,
	opts ...Option,
) (*PriorityQueue, error) {
	options := defaultPriorityQueueOptions
	for _, opt := range opts {
		opt(&options)
	}

	parts, err := initializePriorityQueueParts(ctx, &options)
	if err != nil {
		return nil, err
	}

	if parts.activeQ == nil {
		return nil, fmt.Errorf("active queue is not configured")
	}
	if parts.backoffQ == nil {
		return nil, fmt.Errorf("backoff queues are not configured")
	}
	if parts.nominator == nil {
		return nil, fmt.Errorf("nominator is not configured")
	}
	if parts.unschedulablePods == nil {
		return nil, fmt.Errorf("unschedulable pods is not configured")
	}

	return buildPriorityQueue(
		options,
		parts,
	), nil
}

// Run starts the goroutine to pump from backoffQ to activeQ
func (p *PriorityQueue) Run(logger klog.Logger) {
}

func (p *PriorityQueue) FlushBackoffQCompletedOnce(logger klog.Logger) int {
	return p.flushBackoffQCompleted(logger)
}

func (p *PriorityQueue) FlushUnschedulablePodsLeftoverOnce(logger klog.Logger) int {
	return p.flushUnschedulablePodsLeftover(logger)
}

// moveToActiveQ tries to add the pod to the active queue.
// If the pod doesn't pass PreEnqueue plugins, it gets added to unschedulablePods instead.
// It returns whether the move succeeded, was skipped, or failed to persist.
func (p *PriorityQueue) moveToActiveQ(logger klog.Logger, pInfo *framework.QueuedPodInfo, event string) queueTransitionResult {
	result := queueTransitionSkipped

	p.activeQ.underLock(func(unlockedActiveQ unlockedActiveQueuer) {
		if unlockedActiveQ.has(pInfo) {
			return
		}
		if p.backoffQ != nil && p.backoffQ.has(pInfo) {
			return
		}
		if p.unschedulablePods != nil && p.unschedulablePods.get(pInfo.Pod) != nil {
			// fine, we will delete it below after adding
		}

		if pInfo.InitialAttemptTimestamp == nil {
			now := p.clock.Now()
			pInfo.InitialAttemptTimestamp = &now
		}

		if !unlockedActiveQ.add(pInfo, event) {
			result = queueTransitionWriteFailed
			return
		}
		result = queueTransitionMoved

		if p.unschedulablePods != nil {
			p.unschedulablePods.delete(pInfo.Pod, pInfo.Gated)
		}
		if p.backoffQ != nil {
			p.backoffQ.delete(pInfo)
		}

		logger.V(5).Info("Pod moved to an internal scheduling queue", "pod", klog.KObj(pInfo.Pod), "event", event, "queue", activeQ)

		// Only the normal scheduler path needs nominator updates.
		if p.nominator != nil &&
			(event == framework.EventUnscheduledPodAdd.Label() || event == framework.EventUnscheduledPodUpdate.Label()) {
			p.AddNominatedPod(logger, pInfo.PodInfo, nil)
		}
	})

	return result
}

// moveToBackoffQ tries to add the pod to the backoff queue.
// If SchedulerPopFromBackoffQ feature gate is enabled and the pod doesn't pass PreEnqueue plugins, it gets added to unschedulablePods instead.
// It returns whether the move succeeded or failed to persist.
func (p *PriorityQueue) moveToBackoffQ(logger klog.Logger, pInfo *framework.QueuedPodInfo, event string) queueTransitionResult {
	if !p.backoffQ.add(logger, pInfo, event) {
		return queueTransitionWriteFailed
	}
	logger.V(5).Info("Pod moved to an internal scheduling queue", "pod", klog.KObj(pInfo.Pod), "event", event, "queue", backoffQ)
	return queueTransitionMoved
}

// Add adds a pod to the active queue. It should be called only when a new pod
// is added so there is no chance the pod is already in active/unschedulable/backoff queues
func (p *PriorityQueue) Add(logger klog.Logger, pod *v1.Pod) {
	p.lock.Lock()
	defer p.lock.Unlock()

	pInfo := p.newQueuedPodInfo(pod)
	if p.moveToActiveQ(logger, pInfo, framework.EventUnscheduledPodAdd.Label()) == queueTransitionMoved {
		p.activeQ.broadcast()
	}
}

// Activate moves the given pods to activeQ.
// If a pod isn't found in unschedulablePods or backoffQ and it's in-flight,
// the wildcard event is registered so that the pod will be requeued when it comes back.
// But, if a pod isn't found in unschedulablePods or backoffQ and it's not in-flight (i.e., completely unknown pod),
// Activate would ignore the pod.
func (p *PriorityQueue) Activate(logger klog.Logger, pods map[string]*v1.Pod) {
	p.lock.Lock()
	defer p.lock.Unlock()

	for _, pod := range pods {
		_ = p.activate(logger, pod)
	}
}

func (p *PriorityQueue) activate(logger klog.Logger, pod *v1.Pod) bool {
	var pInfo *framework.QueuedPodInfo

	if pInfo = p.unschedulablePods.get(pod); pInfo == nil {
		var exists bool
		pInfo, exists = p.backoffQ.get(newQueuedPodInfoForLookup(pod))
		if !exists {
			return false
		}
		if deleted := p.backoffQ.delete(pInfo); !deleted {
			return false
		}
	}

	if pInfo == nil {
		logger.Error(nil, "Internal error: cannot obtain pInfo")
		return false
	}

	return p.moveToActiveQ(logger, pInfo, framework.ForceActivate) == queueTransitionMoved
}

// SchedulingCycle returns current scheduling cycle.
func (p *PriorityQueue) SchedulingCycle() int64 {
	return p.activeQ.schedulingCycle()
}

// addUnschedulableIfNotPresentWithoutQueueingHint inserts a pod that cannot be scheduled into
// the queue, unless it is already in the queue. Normally, PriorityQueue puts
// unschedulable pods in `unschedulablePods`. But if there has been a recent move
// request, then the pod is put in `backoffQ`.
// TODO: This function is called only when p.isSchedulingQueueHintEnabled is false,
// and this will be removed after SchedulingQueueHint goes to stable and the feature gate is removed.
func (p *PriorityQueue) addUnschedulableWithoutQueueingHint(logger klog.Logger, pInfo *framework.QueuedPodInfo, podSchedulingCycle int64) error {
	pod := pInfo.Pod
	// Refresh the timestamp since the pod is re-added.
	pInfo.Timestamp = p.clock.Now()

	// When the queueing hint is enabled, they are used differently.
	// But, we use all of them as UnschedulablePlugins when the queueing hint isn't enabled so that we don't break the old behaviour.
	rejectorPlugins := pInfo.UnschedulablePlugins.Union(pInfo.PendingPlugins)

	// If a move request has been received, move it to the BackoffQ, otherwise move
	// it to unschedulablePods.
	for plugin := range rejectorPlugins {
		metrics.UnschedulableReason(plugin, pInfo.Pod.Spec.SchedulerName).Inc()
	}
	if p.moveRequestCycle >= podSchedulingCycle || len(rejectorPlugins) == 0 {
		// Two cases to move a Pod to the active/backoff queue:
		// - The Pod is rejected by some plugins, but a move request is received after this Pod's scheduling cycle is started.
		//   In this case, the received event may be make Pod schedulable and we should retry scheduling it.
		// - No unschedulable plugins are associated with this Pod,
		//   meaning something unusual (a temporal failure on kube-apiserver, etc) happened and this Pod gets moved back to the queue.
		//   In this case, we should retry scheduling it because this Pod may not be retried until the next flush.
		if p.moveToBackoffQ(logger, pInfo, framework.ScheduleAttemptFailure) == queueTransitionMoved {
		}
	} else {
		p.unschedulablePods.addOrUpdate(pInfo, framework.ScheduleAttemptFailure)
		logger.V(5).Info("Pod moved to an internal scheduling queue", "pod", klog.KObj(pod), "event", framework.ScheduleAttemptFailure, "queue", unschedulablePods)
	}

	return nil
}

// AddUnschedulableIfNotPresent inserts a pod that cannot be scheduled into
// the queue, unless it is already in the queue. Normally, PriorityQueue puts
// unschedulable pods in `unschedulablePods`. But if there has been a recent move
// request, then the pod is put in `backoffQ`.
func (p *PriorityQueue) AddUnschedulableIfNotPresent(logger klog.Logger, pInfo *framework.QueuedPodInfo, podSchedulingCycle int64) error {
	p.lock.Lock()
	defer p.lock.Unlock()

	// In any case, this Pod will be moved back to the queue and we should call Done.
	defer p.Done(pInfo.Pod.UID)

	pod := pInfo.Pod
	if p.unschedulablePods.get(pod) != nil {
		return fmt.Errorf("pod %v is already present in unschedulable queue", klog.KObj(pod))
	}
	if p.activeQ.has(pInfo) {
		return fmt.Errorf("pod %v is already present in the active queue", klog.KObj(pod))
	}
	if p.backoffQ.has(pInfo) {
		return fmt.Errorf("pod %v is already present in the backoff queue", klog.KObj(pod))
	}

	return p.addUnschedulableWithoutQueueingHint(logger, pInfo, podSchedulingCycle)
}

// flushBackoffQCompleted Moves all pods from backoffQ which have completed backoff in to activeQ
func (p *PriorityQueue) flushBackoffQCompleted(logger klog.Logger) int {
	p.lock.Lock()
	defer p.lock.Unlock()

	if p.backoffQ == nil || p.activeQ == nil {
		logger.V(2).Info("Skipping backoff flush because required queue parts are not configured")
		return 0
	}

	activated := 0
	podsCompletedBackoff := p.backoffQ.popAllBackoffCompleted(logger)
	for _, pInfo := range podsCompletedBackoff {
		switch p.moveToActiveQ(logger, pInfo, framework.BackoffComplete) {
		case queueTransitionMoved:
			activated++
		case queueTransitionWriteFailed:
			p.backoffQ.add(logger, pInfo, "backoffFlushRetry")
		}
	}

	if activated > 0 {
		p.activeQ.broadcast()
	}
	return activated
}

// flushUnschedulablePodsLeftover moves pods which stay in unschedulablePods
// longer than podMaxInUnschedulablePodsDuration to backoffQ or activeQ.
func (p *PriorityQueue) flushUnschedulablePodsLeftover(logger klog.Logger) int {
	p.lock.Lock()
	defer p.lock.Unlock()

	if p.unschedulablePods == nil || p.backoffQ == nil || p.activeQ == nil {
		logger.V(2).Info("Skipping unschedulable flush because required queue parts are not configured")
		return 0
	}

	cutoff := p.clock.Now().Add(-p.podMaxInUnschedulablePodsDuration)
	candidates, err := p.unschedulablePods.listOlderThan(context.Background(), cutoff)
	if err != nil {
		logger.Error(err, "Unable to list leftover unschedulable pods")
		return 0
	}

	moved := 0
	activated := false

	for _, entry := range candidates {
		claimed, err := p.unschedulablePods.deleteIfVersion(
			context.Background(),
			entry.PInfo.Pod,
			entry.Version,
			entry.PInfo.Gated,
		)
		if err != nil {
			logger.Error(err, "Unable to claim unschedulable pod for flush", "pod", klog.KObj(entry.PInfo.Pod))
			continue
		}
		if !claimed {
			continue
		}

		result := queueTransitionSkipped
		stillBackingOff := p.backoffQ.isPodBackingoff(entry.PInfo)
		if stillBackingOff {
			result = p.moveToBackoffQ(logger, entry.PInfo, framework.EventUnschedulableTimeout.Label())
		} else {
			result = p.moveToActiveQ(logger, entry.PInfo, framework.EventUnschedulableTimeout.Label())
		}

		switch result {
		case queueTransitionMoved:
			moved++
			if !stillBackingOff {
				activated = true
			}
		case queueTransitionWriteFailed:
			p.unschedulablePods.addOrUpdate(entry.PInfo, "unschedulableFlushRetry")
		}
	}

	if activated {
		p.activeQ.broadcast()
	}
	return moved
}

func (p *PriorityQueue) Pop(logger klog.Logger) (*framework.QueuedPodInfo, error) {
	return p.activeQ.pop(logger)
}

// Done must be called for pod returned by Pop. This allows the queue to
// keep track of which pods are currently being processed.
func (p *PriorityQueue) Done(pod types.UID) {
	// do nothing if schedulingQueueHint is disabled.
	// In that case, we don't have inFlightPods and inFlightEvents.
	return
}

// isPodUpdated checks if the pod is updated in a way that it may have become
// schedulable. It drops status of the pod and compares it with old version,
// except for pod.status.resourceClaimStatuses: changing that may have an
// effect on scheduling.
func isPodUpdated(oldPod, newPod *v1.Pod) bool {
	strip := func(pod *v1.Pod) *v1.Pod {
		p := pod.DeepCopy()
		p.ResourceVersion = ""
		p.Generation = 0
		p.Status = v1.PodStatus{
			ResourceClaimStatuses: pod.Status.ResourceClaimStatuses,
		}
		p.ManagedFields = nil
		p.Finalizers = nil
		return p
	}
	return !reflect.DeepEqual(strip(oldPod), strip(newPod))
}

// Update updates a pod in the active or backoff queue if present. Otherwise, it removes
// the item from the unschedulable queue if pod is updated in a way that it may
// become schedulable and adds the updated one to the active queue.
// If pod is not present in any of the queues, it is added to the active queue.
func (p *PriorityQueue) Update(logger klog.Logger, oldPod, newPod *v1.Pod) {
	p.lock.Lock()
	defer p.lock.Unlock()

	if oldPod != nil {
		oldPodInfo := newQueuedPodInfoForLookup(oldPod)
		// If the pod is already in the active queue, just update it there.
		if pInfo := p.activeQ.update(newPod, oldPodInfo); pInfo != nil {
			p.UpdateNominatedPod(logger, oldPod, pInfo.PodInfo)
			return
		}

		// If the pod is in the backoff queue, update it there.
		if pInfo := p.backoffQ.update(newPod, oldPodInfo); pInfo != nil {
			p.UpdateNominatedPod(logger, oldPod, pInfo.PodInfo)
			return
		}
	}

	// If the pod is in the unschedulable queue, updating it may make it schedulable.
	if pInfo := p.unschedulablePods.get(newPod); pInfo != nil {
		_ = pInfo.Update(newPod)
		p.UpdateNominatedPod(logger, oldPod, pInfo.PodInfo)
		gated := pInfo.Gated
		if isPodUpdated(oldPod, newPod) {
			// Pod might have completed its backoff time while being in unschedulablePods,
			// so we should check isPodBackingoff before moving the pod to backoffQ.
			if p.backoffQ.isPodBackingoff(pInfo) {
				if p.moveToBackoffQ(logger, pInfo, framework.EventUnscheduledPodUpdate.Label()) == queueTransitionMoved {
					p.unschedulablePods.delete(pInfo.Pod, gated)
				}
				return
			}

			if p.moveToActiveQ(logger, pInfo, framework.EventUnscheduledPodUpdate.Label()) == queueTransitionMoved {
				p.activeQ.broadcast()
			}
			return
		}

		// Pod update didn't make it schedulable, keep it in the unschedulable queue.
		p.unschedulablePods.addOrUpdate(pInfo, framework.EventUnscheduledPodUpdate.Label())
		return
	}
	// If pod is not in any of the queues, we put it in the active queue.
	pInfo := p.newQueuedPodInfo(newPod)
	if p.moveToActiveQ(logger, pInfo, framework.EventUnscheduledPodUpdate.Label()) == queueTransitionMoved {
		p.activeQ.broadcast()
	}
}

// Delete deletes the item from either of the two queues. It assumes the pod is
// only in one queue.
func (p *PriorityQueue) Delete(pod *v1.Pod) {
	p.lock.Lock()
	defer p.lock.Unlock()

	if p.nominator != nil {
		p.DeleteNominatedPodIfExists(pod)
	}

	pInfo := newQueuedPodInfoForLookup(pod)
	if err := p.activeQ.delete(pInfo); err == nil {
		return
	}
	if p.backoffQ != nil {
		if deleted := p.backoffQ.delete(pInfo); deleted {
			return
		}
	}
	if p.unschedulablePods != nil {
		if pInfo = p.unschedulablePods.get(pod); pInfo != nil {
			p.unschedulablePods.delete(pod, pInfo.Gated)
		}
	}
}

// AssignedPodAdded is called when a bound pod is added. Creation of this pod
// may make pending pods with matching affinity terms schedulable.
func (p *PriorityQueue) AssignedPodAdded(logger klog.Logger, pod *v1.Pod) {
	nsLabels := p.getNamespaceLabelsSnapshot(logger, pod.Namespace)

	p.lock.Lock()

	// Pre-filter Pods to move by getUnschedulablePodsWithCrossTopologyTerm
	// because Pod related events shouldn't make Pods that rejected by single-node scheduling requirement schedulable.
	p.movePodsToActiveOrBackoffQueue(logger, p.getUnschedulablePodsWithCrossTopologyTerm(pod, nsLabels), framework.EventAssignedPodAdd, nil, pod)
	p.lock.Unlock()
}

// AssignedPodUpdated is called when a bound pod is updated. Change of labels
// may make pending pods with matching affinity terms schedulable.
func (p *PriorityQueue) AssignedPodUpdated(logger klog.Logger, oldPod, newPod *v1.Pod, event framework.ClusterEvent) {
	nsLabels := p.getNamespaceLabelsSnapshot(logger, newPod.Namespace)

	p.lock.Lock()
	if (framework.ClusterEvent{Resource: framework.Pod, ActionType: framework.UpdatePodScaleDown}.Match(event)) {
		// In this case, we don't want to pre-filter Pods by getUnschedulablePodsWithCrossTopologyTerm
		// because Pod related events may make Pods that were rejected by NodeResourceFit schedulable.
		p.moveAllToActiveOrBackoffQueue(logger, event, oldPod, newPod, nil)
	} else {
		// Pre-filter Pods to move by getUnschedulablePodsWithCrossTopologyTerm
		// because Pod related events only make Pods rejected by cross topology term schedulable.
		p.movePodsToActiveOrBackoffQueue(logger, p.getUnschedulablePodsWithCrossTopologyTerm(newPod, nsLabels), event, oldPod, newPod)
	}
	p.lock.Unlock()
}

// NOTE: this function assumes a lock has been acquired in the caller.
// moveAllToActiveOrBackoffQueue moves all pods from unschedulablePods to activeQ or backoffQ.
// This function adds all pods and then signals the condition variable to ensure that
// if Pop() is waiting for an item, it receives the signal after all the pods are in the
// queue and the head is the highest priority pod.
func (p *PriorityQueue) moveAllToActiveOrBackoffQueue(logger klog.Logger, event framework.ClusterEvent, oldObj, newObj interface{}, preCheck PreEnqueueCheck) {
	unschedulableList := p.unschedulablePods.list()
	unschedulablePods := make([]*framework.QueuedPodInfo, 0, len(unschedulableList))

	for _, pInfo := range unschedulableList {
		if preCheck == nil || preCheck(pInfo.Pod) {
			unschedulablePods = append(unschedulablePods, pInfo)
		}
	}

	p.movePodsToActiveOrBackoffQueue(logger, unschedulablePods, event, oldObj, newObj)
}

// MoveAllToActiveOrBackoffQueue moves all pods from unschedulablePods to activeQ or backoffQ.
// This function adds all pods and then signals the condition variable to ensure that
// if Pop() is waiting for an item, it receives the signal after all the pods are in the
// queue and the head is the highest priority pod.
func (p *PriorityQueue) MoveAllToActiveOrBackoffQueue(logger klog.Logger, event framework.ClusterEvent, oldObj, newObj interface{}, preCheck PreEnqueueCheck) {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.moveAllToActiveOrBackoffQueue(logger, event, oldObj, newObj, preCheck)
}

// NOTE: this function assumes lock has been acquired in caller
func (p *PriorityQueue) movePodsToActiveOrBackoffQueue(logger klog.Logger, podInfoList []*framework.QueuedPodInfo, event framework.ClusterEvent, oldObj, newObj interface{}) {
	for _, pInfo := range podInfoList {
		p.unschedulablePods.delete(pInfo.Pod, pInfo.Gated)

		if p.backoffQ.isPodBackingoff(pInfo) {
			p.moveToBackoffQ(logger, pInfo, event.Label())
		} else {
			p.moveToActiveQ(logger, pInfo, event.Label())
		}
	}

	p.moveRequestCycle = p.activeQ.schedulingCycle()
}

func (p *PriorityQueue) getNamespaceLabelsSnapshot(logger klog.Logger, ns string) (nsLabels labels.Set) {
	if p.kubeClient == nil {
		logger.V(3).Info("kubeClient is nil, assuming empty set of namespace labels", "namespace", ns)
		return
	}

	podNS, err := p.kubeClient.CoreV1().Namespaces().Get(context.TODO(), ns, metav1.GetOptions{})
	if err == nil {
		return labels.Merge(podNS.Labels, nil)
	}

	logger.V(3).Info("getting namespace, assuming empty set of namespace labels", "namespace", ns, "err", err)
	return
}

// getUnschedulablePodsWithCrossTopologyTerm returns unschedulable pods which either of following conditions is met:
// - have any affinity term that matches "pod".
// - rejected by PodTopologySpread plugin.
// NOTE: this function assumes lock has been acquired in caller.
func (p *PriorityQueue) getUnschedulablePodsWithCrossTopologyTerm(pod *v1.Pod, nsLabels labels.Set) []*framework.QueuedPodInfo {
	var podsToMove []*framework.QueuedPodInfo
	for _, pInfo := range p.unschedulablePods.list() {
		if pInfo.UnschedulablePlugins.Has(podtopologyspread.Name) && pod.Namespace == pInfo.Pod.Namespace {
			podsToMove = append(podsToMove, pInfo)
			continue
		}

		for _, term := range pInfo.RequiredAffinityTerms {
			if term.Matches(pod, nsLabels) {
				podsToMove = append(podsToMove, pInfo)
				break
			}
		}
	}

	return podsToMove
}

// PodsInActiveQ returns all the Pods in the activeQ.
func (p *PriorityQueue) PodsInActiveQ() []*v1.Pod {
	return p.activeQ.list()
}

// PodsInBackoffQ returns all the Pods in the backoffQ.
func (p *PriorityQueue) PodsInBackoffQ() []*v1.Pod {
	return p.backoffQ.list()
}

// UnschedulablePods returns all the pods in unschedulable state.
func (p *PriorityQueue) UnschedulablePods() []*v1.Pod {
	var result []*v1.Pod
	for _, pInfo := range p.unschedulablePods.list() {
		result = append(result, pInfo.Pod)
	}
	return result
}

var pendingPodsSummary = "activeQ:%v; backoffQ:%v; unschedulablePods:%v"

// GetPod searches for a pod in the activeQ, backoffQ, and unschedulablePods.
func (p *PriorityQueue) GetPod(name, namespace string) (pInfo *framework.QueuedPodInfo, ok bool) {
	p.lock.RLock()
	defer p.lock.RUnlock()

	pInfoLookup := &framework.QueuedPodInfo{
		PodInfo: &framework.PodInfo{
			Pod: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: namespace,
				},
			},
		},
	}
	if pInfo, ok = p.backoffQ.get(pInfoLookup); ok {
		return pInfo, true
	}
	if pInfo = p.unschedulablePods.get(pInfoLookup.Pod); pInfo != nil {
		return pInfo, true
	}

	p.activeQ.underRLock(func(unlockedActiveQ unlockedActiveQueueReader) {
		pInfo, ok = unlockedActiveQ.get(pInfoLookup)
	})
	return
}

// PendingPods returns all the pending pods in the queue; accompanied by a debugging string
// recording showing the number of pods in each queue respectively.
// This function is used for debugging purposes in the scheduler cache dumper and comparer.
func (p *PriorityQueue) PendingPods() ([]*v1.Pod, string) {
	p.lock.RLock()
	defer p.lock.RUnlock()
	result := p.PodsInActiveQ()
	activeQLen := len(result)

	backoffQPods := p.PodsInBackoffQ()
	backoffQLen := len(backoffQPods)
	result = append(result, backoffQPods...)

	unschedulableList := p.unschedulablePods.list()
	for _, pInfo := range unschedulableList {
		result = append(result, pInfo.Pod)
	}

	return result, fmt.Sprintf(pendingPodsSummary, activeQLen, backoffQLen, len(unschedulableList))
}

// Note: this function assumes the caller locks both p.lock.RLock and p.activeQ.getLock().RLock.
func (p *PriorityQueue) nominatedPodToInfo(np podRef, unlockedActiveQ unlockedActiveQueueReader) *framework.PodInfo {
	pod := np.toPod()
	pInfoLookup := newQueuedPodInfoForLookup(pod)

	queuedPodInfo, exists := unlockedActiveQ.get(pInfoLookup)
	if exists {
		return queuedPodInfo.PodInfo
	}

	queuedPodInfo = p.unschedulablePods.get(pod)
	if queuedPodInfo != nil {
		return queuedPodInfo.PodInfo
	}

	queuedPodInfo, exists = p.backoffQ.get(pInfoLookup)
	if exists {
		return queuedPodInfo.PodInfo
	}

	return &framework.PodInfo{Pod: pod}
}

// Close closes the priority queue.
func (p *PriorityQueue) Close() {
	p.lock.Lock()
	defer p.lock.Unlock()
	close(p.stop)
	p.activeQ.close()
	p.activeQ.broadcast()
}

// NominatedPodsForNode returns a copy of pods that are nominated to run on the given node,
// but they are waiting for other pods to be removed from the node.
// CAUTION: Make sure you don't call this function while taking any queue's lock in any scenario.
func (p *PriorityQueue) NominatedPodsForNode(nodeName string) []*framework.PodInfo {
	p.lock.RLock()
	defer p.lock.RUnlock()
	nominatedPods := p.nominator.nominatedPodsForNode(nodeName)

	pods := make([]*framework.PodInfo, len(nominatedPods))
	p.activeQ.underRLock(func(unlockedActiveQ unlockedActiveQueueReader) {
		for i, np := range nominatedPods {
			pods[i] = p.nominatedPodToInfo(np, unlockedActiveQ).DeepCopy()
		}
	})
	return pods
}

// newQueuedPodInfo builds a QueuedPodInfo object.
func (p *PriorityQueue) newQueuedPodInfo(pod *v1.Pod, plugins ...string) *framework.QueuedPodInfo {
	now := p.clock.Now()
	// ignore this err since apiserver doesn't properly validate affinity terms
	// and we can't fix the validation for backwards compatibility.
	podInfo, _ := framework.NewPodInfo(pod)
	return &framework.QueuedPodInfo{
		PodInfo:                 podInfo,
		Timestamp:               now,
		InitialAttemptTimestamp: nil,
		UnschedulablePlugins:    sets.New(plugins...),
	}
}

func podInfoKeyFunc(pInfo *framework.QueuedPodInfo) string {
	return cache.NewObjectName(pInfo.Pod.Namespace, pInfo.Pod.Name).String()
}
