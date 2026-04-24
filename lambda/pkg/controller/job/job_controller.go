/*
Copyright 2015 The Kubernetes Authors.

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

package job

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"lambda/pkg/controller/awsstore"

	batch "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/json"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	v1core "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog/v2"
	podutil "k8s.io/kubernetes/pkg/api/v1/pod"
	"k8s.io/kubernetes/pkg/controller"
	"k8s.io/kubernetes/pkg/controller/job/util"
	"k8s.io/utils/clock"
	"k8s.io/utils/ptr"
)

// controllerKind contains the schema.GroupVersionKind for this controller type.
var controllerKind = batch.SchemeGroupVersion.WithKind("Job")

var (
	// syncJobBatchPeriod is the batch period for controller sync invocations for a Job.
	syncJobBatchPeriod = time.Second
	// DefaultJobPodFailureBackOff is the default pod failure backoff period. Exported for tests.
	DefaultJobPodFailureBackOff = 10 * time.Second
	// MaxJobPodFailureBackOff is the max  pod failure backoff period. Exported for tests.
	MaxJobPodFailureBackOff = 10 * time.Minute
	// MaxUncountedPods is the maximum size the slices in
	// .status.uncountedTerminatedPods should have to keep their representation
	// roughly below 20 KB. Exported for tests
	MaxUncountedPods = 500
	// MaxPodCreateDeletePerSync is the maximum number of pods that can be
	// created or deleted in a single sync call. Exported for tests.
	MaxPodCreateDeletePerSync = 500
)

// Controller ensures that all Job objects have corresponding pods to
// run their configured workload.
type Controller struct {
	kubeClient clientset.Interface
	podControl controller.PodControlInterface

	// To allow injection of the following for testing.
	updateStatusHandler func(ctx context.Context, job *batch.Job) (*batch.Job, error)
	patchJobHandler     func(ctx context.Context, job *batch.Job, patch []byte) error

	broadcaster record.EventBroadcaster
	recorder    record.EventRecorder

	clock clock.WithTicker

	// Store with information to compute the expotential backoff delay for pod
	// recreation in case of pod failures.
	podBackoffStore *backoffStore

	// SQS-backed queues used by the serverless controller.
	jobQueue                     awsstore.SQSQueue
	jobQueueBatchSize            int32
	jobQueueVisibilityTimeout    time.Duration
	orphanQueue                  awsstore.SQSQueue
	orphanQueueBatchSize         int32
	orphanQueueVisibilityTimeout time.Duration
}

type syncJobCtx struct {
	job                             *batch.Job
	pods                            []*v1.Pod
	finishedCondition               *batch.JobCondition
	activePods                      []*v1.Pod
	succeeded                       int32
	failed                          int32
	prevSucceededIndexes            orderedIntervals
	succeededIndexes                orderedIntervals
	failedIndexes                   *orderedIntervals
	newBackoffRecord                backoffRecord
	uncounted                       *uncountedTerminatedPods
	podsWithDelayedDeletionPerIndex map[int]*v1.Pod
	terminating                     *int32
	ready                           int32
}

type orphanPodKeyKind int

const (
	// "key"
	OrphanPodKeyKindName orphanPodKeyKind = iota
	// "selector"
	OrphanPodKeyKindSelector
)

type orphanPodKey struct {
	// Either "name" or "selector"
	kind      orphanPodKeyKind
	namespace string
	// Either "pod name" or "pod selector"
	value string
}

type orphanPodMessage struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Value     string `json:"value"`
}

const (
	DefaultJobQueueBatchSize            int32         = 10
	DefaultJobQueueVisibilityTimeout    time.Duration = 30 * time.Second
	DefaultOrphanQueueBatchSize         int32         = 10
	DefaultOrphanQueueVisibilityTimeout time.Duration = 30 * time.Second
)

// Option configures a Controller for lambda use.
type Option func(*Controller)

func WithJobQueueBatchSize(size int32) Option {
	return func(jm *Controller) {
		if size > 0 {
			jm.jobQueueBatchSize = size
		}
	}
}

func WithJobQueueVisibilityTimeout(d time.Duration) Option {
	return func(jm *Controller) {
		if d >= 0 {
			jm.jobQueueVisibilityTimeout = d
		}
	}
}

func WithOrphanQueueBatchSize(size int32) Option {
	return func(jm *Controller) {
		if size > 0 {
			jm.orphanQueueBatchSize = size
		}
	}
}

func WithOrphanQueueVisibilityTimeout(d time.Duration) Option {
	return func(jm *Controller) {
		if d >= 0 {
			jm.orphanQueueVisibilityTimeout = d
		}
	}
}

// Result summarises the outcome of a single RunOnce invocation.
type Result struct {
	JobsDequeued    int `json:"jobsDequeued"`
	JobsSynced      int `json:"jobsSynced"`
	JobsFailed      int `json:"jobsFailed"`
	OrphansDequeued int `json:"orphansDequeued"`
	OrphansSynced   int `json:"orphansSynced"`
	OrphansFailed   int `json:"orphansFailed"`
}

// NewLambdaController creates the serverless job controller. Reconciliation
// requests and orphan cleanups are both driven by SQS queues.
func NewLambdaController(jobQueue awsstore.SQSQueue, orphanQueue awsstore.SQSQueue, kubeClient clientset.Interface, opts ...Option) (*Controller, error) {
	if kubeClient == nil {
		return nil, fmt.Errorf("nil kube client")
	}
	if jobQueue == nil {
		return nil, fmt.Errorf("nil job queue")
	}
	if orphanQueue == nil {
		return nil, fmt.Errorf("nil orphan queue")
	}

	// Use context.Background() so the broadcaster outlives the init context.
	eventBroadcaster := record.NewBroadcaster(record.WithContext(context.Background()))
	eventBroadcaster.StartStructuredLogging(3)
	eventBroadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: kubeClient.CoreV1().Events("")})

	jm := &Controller{
		kubeClient: kubeClient,
		podControl: controller.RealPodControl{
			KubeClient: kubeClient,
			Recorder:   eventBroadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: "job-controller"}),
		},
		jobQueue:                     jobQueue,
		orphanQueue:                  orphanQueue,
		broadcaster:                  eventBroadcaster,
		recorder:                     eventBroadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: "job-controller"}),
		clock:                        &clock.RealClock{},
		podBackoffStore:              newBackoffStore(),
		jobQueueBatchSize:            DefaultJobQueueBatchSize,
		jobQueueVisibilityTimeout:    DefaultJobQueueVisibilityTimeout,
		orphanQueueBatchSize:         DefaultOrphanQueueBatchSize,
		orphanQueueVisibilityTimeout: DefaultOrphanQueueVisibilityTimeout,
	}

	jm.updateStatusHandler = jm.updateJobStatus
	jm.patchJobHandler = jm.patchJob

	for _, opt := range opts {
		opt(jm)
	}

	return jm, nil
}

func encodeOrphanPodKey(key orphanPodKey) (string, error) {
	msg := orphanPodMessage{
		Namespace: key.namespace,
		Value:     key.value,
	}
	switch key.kind {
	case OrphanPodKeyKindName:
		msg.Kind = "name"
	case OrphanPodKeyKindSelector:
		msg.Kind = "selector"
	default:
		return "", fmt.Errorf("unknown orphan pod key type: %d", key.kind)
	}
	if strings.TrimSpace(msg.Namespace) == "" || strings.TrimSpace(msg.Value) == "" {
		return "", fmt.Errorf("orphan pod key is missing namespace or value")
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return "", fmt.Errorf("marshal orphan pod key: %w", err)
	}
	return string(data), nil
}

func decodeOrphanPodKey(body string) (orphanPodKey, error) {
	body = strings.TrimSpace(body)
	if body == "" {
		return orphanPodKey{}, fmt.Errorf("empty orphan pod queue item")
	}

	var msg orphanPodMessage
	if err := json.Unmarshal([]byte(body), &msg); err != nil {
		return orphanPodKey{}, fmt.Errorf("unmarshal orphan pod key: %w", err)
	}

	key := orphanPodKey{
		namespace: strings.TrimSpace(msg.Namespace),
		value:     strings.TrimSpace(msg.Value),
	}
	switch strings.TrimSpace(msg.Kind) {
	case "name":
		key.kind = OrphanPodKeyKindName
	case "selector":
		key.kind = OrphanPodKeyKindSelector
	default:
		return orphanPodKey{}, fmt.Errorf("unknown orphan pod key kind %q", msg.Kind)
	}
	if key.namespace == "" || key.value == "" {
		return orphanPodKey{}, fmt.Errorf("orphan pod key is missing namespace or value")
	}
	return key, nil
}

func (jm *Controller) enqueueJobKeyAfter(ctx context.Context, key string, delay time.Duration) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return fmt.Errorf("empty job key")
	}
	if delay < 0 {
		delay = 0
	}
	return jm.jobQueue.EnqueueAfter(ctx, key, delay)
}

func (jm *Controller) enqueueSyncJobWithDelay(ctx context.Context, logger klog.Logger, obj interface{}, delay time.Duration) error {
	if delay < syncJobBatchPeriod {
		delay = syncJobBatchPeriod
	}

	key, err := controller.KeyFunc(obj)
	if err != nil {
		return fmt.Errorf("get job key: %w", err)
	}

	logger.V(2).Info("enqueueing job", "key", key, "delay", delay)
	return jm.enqueueJobKeyAfter(ctx, key, delay)
}

func (jm *Controller) enqueueOrphanPod(ctx context.Context, key orphanPodKey) error {
	body, err := encodeOrphanPodKey(key)
	if err != nil {
		return err
	}
	return jm.orphanQueue.EnqueueAfter(ctx, body, 0)
}

// RunOnce dequeues a batch of job keys from the SQS queue, reconciles each
// job via syncJob, then dequeues and processes orphan cleanups. Failed
// messages are left in SQS and become visible again after the visibility
// timeout, giving the next invocation a chance to retry.
func (jm *Controller) RunOnce(ctx context.Context) (Result, error) {
	logger := klog.FromContext(ctx)

	items, err := jm.jobQueue.Dequeue(ctx, jm.jobQueueBatchSize, jm.jobQueueVisibilityTimeout)
	if err != nil {
		return Result{}, fmt.Errorf("dequeue job keys: %w", err)
	}

	result := Result{JobsDequeued: len(items)}
	var errs []error

	for _, item := range items {
		jobKey := strings.TrimSpace(item.Body)
		if jobKey == "" {
			logger.V(2).Info("Skipping empty job queue message")
			if delErr := jm.jobQueue.Delete(ctx, item.ReceiptHandle); delErr != nil {
				errs = append(errs, fmt.Errorf("delete empty queue item: %w", delErr))
			}
			result.JobsDequeued--
			continue
		}

		if syncErr := jm.syncJob(ctx, jobKey); syncErr != nil {
			logger.Error(syncErr, "Failed to sync job", "key", jobKey)
			errs = append(errs, fmt.Errorf("sync job %q: %w", jobKey, syncErr))
			result.JobsFailed++
			// Leave the message in SQS; it will become visible again after the
			// visibility timeout and be retried on the next invocation.
			continue
		}

		result.JobsSynced++
		if delErr := jm.jobQueue.Delete(ctx, item.ReceiptHandle); delErr != nil {
			errs = append(errs, fmt.Errorf("delete queue item for job %q: %w", jobKey, delErr))
		}
	}

	orphanItems, err := jm.orphanQueue.Dequeue(ctx, jm.orphanQueueBatchSize, jm.orphanQueueVisibilityTimeout)
	if err != nil {
		errs = append(errs, fmt.Errorf("dequeue orphan queue items: %w", err))
		return result, errors.Join(errs...)
	}
	result.OrphansDequeued = len(orphanItems)

	for _, item := range orphanItems {
		key, decodeErr := decodeOrphanPodKey(item.Body)
		if decodeErr != nil {
			errs = append(errs, fmt.Errorf("decode orphan queue item: %w", decodeErr))
			result.OrphansFailed++
			if delErr := jm.orphanQueue.Delete(ctx, item.ReceiptHandle); delErr != nil {
				errs = append(errs, fmt.Errorf("delete malformed orphan queue item: %w", delErr))
			}
			continue
		}

		if syncErr := jm.syncOrphanPod(ctx, key); syncErr != nil {
			logger.Error(syncErr, "Failed to sync orphan pod", "key", key)
			errs = append(errs, fmt.Errorf("sync orphan pod %+v: %w", key, syncErr))
			result.OrphansFailed++
			continue
		}

		result.OrphansSynced++
		if delErr := jm.orphanQueue.Delete(ctx, item.ReceiptHandle); delErr != nil {
			errs = append(errs, fmt.Errorf("delete queue item for orphan %+v: %w", key, delErr))
		}
	}

	logger.Info("Job controller invocation completed",
		"jobsDequeued", result.JobsDequeued,
		"jobsSynced", result.JobsSynced,
		"jobsFailed", result.JobsFailed,
		"orphansDequeued", result.OrphansDequeued,
		"orphansSynced", result.OrphansSynced,
		"orphansFailed", result.OrphansFailed,
	)

	return result, errors.Join(errs...)
}

// ProcessJobItems processes pre-delivered job queue items (from an SQS event trigger) and
// returns the message IDs of items that failed and should be retried.
func (jm *Controller) ProcessJobItems(ctx context.Context, items []awsstore.QueuedItem) (Result, []string) {
	logger := klog.FromContext(ctx)
	result := Result{JobsDequeued: len(items)}
	var failedIDs []string

	for _, item := range items {
		jobKey := strings.TrimSpace(item.Body)
		if jobKey == "" {
			logger.V(2).Info("Skipping empty job queue message")
			result.JobsDequeued--
			continue
		}
		if err := jm.syncJob(ctx, jobKey); err != nil {
			logger.Error(err, "Failed to sync job", "key", jobKey)
			result.JobsFailed++
			failedIDs = append(failedIDs, item.MessageID)
			continue
		}
		result.JobsSynced++
	}
	return result, failedIDs
}

// ProcessOrphanItems processes pre-delivered orphan queue items (from an SQS event trigger) and
// returns the message IDs of items that failed and should be retried.
func (jm *Controller) ProcessOrphanItems(ctx context.Context, items []awsstore.QueuedItem) (Result, []string) {
	logger := klog.FromContext(ctx)
	result := Result{OrphansDequeued: len(items)}
	var failedIDs []string

	for _, item := range items {
		key, decodeErr := decodeOrphanPodKey(item.Body)
		if decodeErr != nil {
			logger.Error(decodeErr, "Failed to decode orphan queue item")
			result.OrphansFailed++
			failedIDs = append(failedIDs, item.MessageID)
			continue
		}
		if err := jm.syncOrphanPod(ctx, key); err != nil {
			logger.Error(err, "Failed to sync orphan pod", "key", key)
			result.OrphansFailed++
			failedIDs = append(failedIDs, item.MessageID)
			continue
		}
		result.OrphansSynced++
	}
	return result, failedIDs
}

// syncOrphanPod removes the tracking finalizer from an orphan pod if found.
func (jm *Controller) syncOrphanPod(ctx context.Context, key orphanPodKey) error {
	startTime := jm.clock.Now()
	logger := klog.FromContext(ctx)
	defer func() {
		logger.V(4).Info("Finished syncing orphan pod", "pod", key, "elapsed", jm.clock.Since(startTime))
	}()

	switch key.kind {
	case OrphanPodKeyKindName:
		pod, err := jm.kubeClient.CoreV1().Pods(key.namespace).Get(ctx, key.value, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				logger.V(4).Info("Orphan pod has been deleted", "pod", klog.KRef(key.namespace, key.value))
				return nil
			}
			return err
		}
		return jm.handleSingleOrphanPod(ctx, pod)
	case OrphanPodKeyKindSelector:
		logger.V(8).Info("syncing all pods matching the label selector", "namespace", key.namespace, "labelSelector", key.value)
		return jm.syncOrphanPodsBySelector(ctx, key.namespace, key.value)
	default:
		return fmt.Errorf("unknown key type: %d", key.kind)
	}
}

// syncOrphanPodsBySelector fetches and processes all pods matching the given label selector.
func (jm *Controller) syncOrphanPodsBySelector(ctx context.Context, namespace string, labelSelector string) error {
	logger := klog.FromContext(ctx)

	// Fetch all pods that match the label selector directly from the API server.
	// Relatively expensive, but only called from the orphan reconciler.
	podList, err := jm.kubeClient.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: labelSelector})
	if err != nil {
		return err
	}
	for i := range podList.Items {
		pod := &podList.Items[i]
		if err := jm.handleSingleOrphanPod(ctx, pod); err != nil {
			logger.Error(err, "syncing orphan pod failed", "pod", klog.KObj(pod))
		}
	}
	return nil
}

// resolveControllerRef returns the controller referenced by a ControllerRef,
// or nil if the ControllerRef could not be resolved to a matching controller
// of the correct Kind.
func (jm *Controller) resolveControllerRef(namespace string, controllerRef *metav1.OwnerReference) *batch.Job {
	if controllerRef.Kind != controllerKind.Kind {
		return nil
	}
	job, err := jm.kubeClient.BatchV1().Jobs(namespace).Get(context.Background(), controllerRef.Name, metav1.GetOptions{})
	if err != nil {
		return nil
	}
	if job.UID != controllerRef.UID {
		return nil
	}
	return job
}

// handleSingleOrphanPod processes a single orphan pod.
func (jm *Controller) handleSingleOrphanPod(ctx context.Context, sharedPod *v1.Pod) error {
	ns := sharedPod.Namespace
	name := sharedPod.Name
	// Make sure the pod is still orphaned.
	if controllerRef := metav1.GetControllerOf(sharedPod); controllerRef != nil {
		if controllerRef.Kind != controllerKind.Kind || controllerRef.APIVersion != batch.SchemeGroupVersion.String() {
			// The pod is controlled by an owner that is not a batch/v1 Job. Do not remove finalizer.
			return nil
		}
		job := jm.resolveControllerRef(ns, controllerRef)
		if job != nil && !util.IsJobFinished(job) {
			// The pod was adopted. Do not remove finalizer.
			return nil
		}
	}
	if patch := removeTrackingFinalizerPatch(sharedPod); patch != nil {
		if err := jm.podControl.PatchPod(ctx, ns, name, patch); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	return nil
}

// getPodsForJob returns the set of pods that this Job should manage.
// It also reconciles ControllerRef by adopting/orphaning, adding tracking
// finalizers.
// Note that the returned Pods are pointers into the cache.
func (jm *Controller) getPodsForJob(ctx context.Context, j *batch.Job) ([]*v1.Pod, error) {
	selector, err := metav1.LabelSelectorAsSelector(j.Spec.Selector)
	if err != nil {
		return nil, fmt.Errorf("couldn't convert Job selector: %v", err)
	}
	// List all pods in the namespace to include those that don't match the
	// selector anymore but have a ControllerRef pointing to this controller.
	podList, err := jm.kubeClient.CoreV1().Pods(j.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	pods := make([]*v1.Pod, 0, len(podList.Items))
	for i := range podList.Items {
		pods = append(pods, &podList.Items[i])
	}
	// If any adoptions are attempted, we should first recheck for deletion
	// with an uncached quorum read sometime after listing Pods (see #42639).
	canAdoptFunc := controller.RecheckDeletionTimestamp(func(ctx context.Context) (metav1.Object, error) {
		fresh, err := jm.kubeClient.BatchV1().Jobs(j.Namespace).Get(ctx, j.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		if fresh.UID != j.UID {
			return nil, fmt.Errorf("original Job %v/%v is gone: got uid %v, wanted %v", j.Namespace, j.Name, fresh.UID, j.UID)
		}
		return fresh, nil
	})
	cm := controller.NewPodControllerRefManager(jm.podControl, j, selector, controllerKind, canAdoptFunc, batch.JobTrackingFinalizer)
	// When adopting Pods, this operation adds an ownerRef and finalizers.
	pods, err = cm.ClaimPods(ctx, pods)
	if err != nil {
		return pods, err
	}
	// Set finalizer on adopted pods for the remaining calculations.
	for i, p := range pods {
		adopted := true
		for _, r := range p.OwnerReferences {
			if r.UID == j.UID {
				adopted = false
				break
			}
		}
		if adopted && !hasJobTrackingFinalizer(p) {
			pods[i] = p.DeepCopy()
			pods[i].Finalizers = append(p.Finalizers, batch.JobTrackingFinalizer)
		}
	}
	return pods, err
}

// syncJob will sync the job with the given key if it has had its expectations fulfilled, meaning
// it did not expect to see any more of its pods created or deleted. This function is not meant to be invoked
// concurrently with the same key.
func (jm *Controller) syncJob(ctx context.Context, key string) (rErr error) {
	startTime := jm.clock.Now()
	logger := klog.FromContext(ctx)
	defer func() {
		logger.V(4).Info("Finished syncing job", "key", key, "elapsed", jm.clock.Since(startTime))
	}()

	ns, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}
	if len(ns) == 0 || len(name) == 0 {
		return fmt.Errorf("invalid job key %q: either namespace or name is missing", key)
	}
	sharedJob, err := jm.kubeClient.BatchV1().Jobs(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			logger.V(4).Info("Job has been deleted", "key", key)

			err := jm.podBackoffStore.removeBackoffRecord(key)
			if err != nil {
				// re-syncing here as the record has to be removed for finished/deleted jobs
				return fmt.Errorf("error removing backoff record %w", err)
			}
			return nil
		}
		return err
	}

	// make a copy so we don't mutate the shared cache
	job := *sharedJob.DeepCopy()

	// if job was finished previously, we don't want to redo the termination
	if util.IsJobFinished(&job) {
		err := jm.podBackoffStore.removeBackoffRecord(key)
		if err != nil {
			// re-syncing here as the record has to be removed for finished/deleted jobs
			return fmt.Errorf("error removing backoff record %w", err)
		}
		return nil
	}

	if job.Spec.CompletionMode != nil && *job.Spec.CompletionMode != batch.NonIndexedCompletion && *job.Spec.CompletionMode != batch.IndexedCompletion {
		jm.recorder.Event(&job, v1.EventTypeWarning, "UnknownCompletionMode", "Skipped Job sync because completion mode is unknown")
		return nil
	}

	if job.Status.UncountedTerminatedPods == nil {
		job.Status.UncountedTerminatedPods = &batch.UncountedTerminatedPods{}
	}

	pods, err := jm.getPodsForJob(ctx, &job)
	if err != nil {
		return err
	}
	activePods := controller.FilterActivePods(logger, pods)
	jobCtx := &syncJobCtx{
		job:        &job,
		pods:       pods,
		activePods: activePods,
		ready:      countReadyPods(activePods),
		uncounted:  newUncountedTerminatedPods(*job.Status.UncountedTerminatedPods),
	}
	if trackTerminatingPods(&job) {
		jobCtx.terminating = ptr.To(controller.CountTerminatingPods(pods))
	}
	active := int32(len(jobCtx.activePods))
	newSucceededPods, newFailedPods := getNewFinishedPods(jobCtx)
	jobCtx.succeeded = job.Status.Succeeded + int32(len(newSucceededPods)) + int32(len(jobCtx.uncounted.succeeded))
	jobCtx.failed = job.Status.Failed + int32(nonIgnoredFailedPodsCount(jobCtx, newFailedPods)) + int32(len(jobCtx.uncounted.failed))

	// Job first start. Set StartTime only if the job is not in the suspended state.
	if job.Status.StartTime == nil && !jobSuspended(&job) {
		now := metav1.NewTime(jm.clock.Now())
		job.Status.StartTime = &now
	}

	jobCtx.newBackoffRecord = jm.podBackoffStore.newBackoffRecord(key, newSucceededPods, newFailedPods)

	var manageJobErr error

	// This is the starting point for evaluating the end state of the Job.
	// Note that we need to order evaluations since a Job could satisfy multiple criteria at the same time in some cases:
	// 1. Evaluate the pre-existing SuccessCriteriaMet and FailureTarget to respect the previous reconcile results, then transform FailureTarget to Failed.
	// 2. Evaluate failure scenarios.
	// 3. Evaluate success scenarios.
	// 4. Evaluate jobCtx.finishedCondition (see trackJobStatusAndRemoveFinalizers), then transform FailureTarget to Failed and SuccessCriteriaMet to Complete once the job is finished.

	exceedsBackoffLimit := jobCtx.failed > *job.Spec.BackoffLimit
	// Evaluate the pre-existing SuccessCriteriaMet.
	jobCtx.finishedCondition = hasSuccessCriteriaMetCondition(&job)

	// Given that the Job already has the SuccessCriteriaMet condition, the termination condition already had confirmed in another cycle.
	// So, the job-controller evaluates the podFailurePolicy only when the Job doesn't have the SuccessCriteriaMet condition.
	if jobCtx.finishedCondition == nil {
		// Evaluate the pre-existing FailureTarget.
		failureTargetCondition := findConditionByType(job.Status.Conditions, batch.JobFailureTarget)
		if failureTargetCondition != nil && failureTargetCondition.Status == v1.ConditionTrue {
			jobCtx.finishedCondition = newFailedConditionForFailureTarget(failureTargetCondition, jm.clock.Now())
			// Evaluate failure scenarios for PodFailurePolicy.
		} else if failJobMessage := getFailJobMessage(&job, pods); failJobMessage != nil {
			// Prepare the interim FailureTarget condition to record the failure message before the finalizers (allowing removal of the pods) are removed.
			jobCtx.finishedCondition = newCondition(batch.JobFailureTarget, v1.ConditionTrue, batch.JobReasonPodFailurePolicy, *failJobMessage, jm.clock.Now())
		}
	}
	// Evaluate failure scenarios for BackoffLimit and ActiveDeadlineSeconds.
	if jobCtx.finishedCondition == nil {
		if exceedsBackoffLimit || pastBackoffLimitOnFailure(&job, pods) {
			// check if the number of pod restart exceeds backoff (for restart OnFailure only)
			// OR if the number of failed jobs increased since the last syncJob
			jobCtx.finishedCondition = jm.newFailureCondition(batch.JobReasonBackoffLimitExceeded, "Job has reached the specified backoff limit")
		} else if jm.pastActiveDeadline(&job) {
			jobCtx.finishedCondition = jm.newFailureCondition(batch.JobReasonDeadlineExceeded, "Job was active longer than specified deadline")
		} else if job.Spec.ActiveDeadlineSeconds != nil && !jobSuspended(&job) {
			syncDuration := time.Duration(*job.Spec.ActiveDeadlineSeconds)*time.Second - jm.clock.Since(job.Status.StartTime.Time)
			logger.V(2).Info("Job has activeDeadlineSeconds configuration. Will sync this job again", "key", key, "nextSyncIn", syncDuration)
			if err := jm.enqueueJobKeyAfter(ctx, key, syncDuration); err != nil {
				return err
			}
		}
	}

	if isIndexedJob(&job) {
		jobCtx.prevSucceededIndexes, jobCtx.succeededIndexes = calculateSucceededIndexes(logger, &job, pods)
		jobCtx.succeeded = int32(jobCtx.succeededIndexes.total())
		// Evaluate failure scenarios for BackoffLimitPerIndex.
		if hasBackoffLimitPerIndex(&job) {
			jobCtx.failedIndexes = calculateFailedIndexes(logger, &job, pods)
			if jobCtx.finishedCondition == nil {
				if job.Spec.MaxFailedIndexes != nil && jobCtx.failedIndexes.total() > int(*job.Spec.MaxFailedIndexes) {
					jobCtx.finishedCondition = jm.newFailureCondition(batch.JobReasonMaxFailedIndexesExceeded, "Job has exceeded the specified maximal number of failed indexes")
				} else if jobCtx.failedIndexes.total() > 0 && jobCtx.failedIndexes.total()+jobCtx.succeededIndexes.total() >= int(*job.Spec.Completions) {
					jobCtx.finishedCondition = jm.newFailureCondition(batch.JobReasonFailedIndexes, "Job has failed indexes")
				}
			}
			jobCtx.podsWithDelayedDeletionPerIndex = getPodsWithDelayedDeletionPerIndex(logger, jobCtx)
		}
		// Evaluate success scenarios for SuccessPolicy.
		if jobCtx.finishedCondition == nil {
			if msg, met := matchSuccessPolicy(logger, job.Spec.SuccessPolicy, *job.Spec.Completions, jobCtx.succeededIndexes); met {
				jobCtx.finishedCondition = newCondition(batch.JobSuccessCriteriaMet, v1.ConditionTrue, batch.JobReasonSuccessPolicy, msg, jm.clock.Now())
			}
		}
	}
	suspendCondChanged := false
	// Remove active pods if Job failed.
	if jobCtx.finishedCondition != nil {
		deletedReady, deleted, err := jm.deleteActivePods(ctx, &job, jobCtx.activePods)
		if deleted != active {
			// Can't declare the Job as finished yet, as there might be remaining
			// pod finalizers or pods that are not in the informer's cache yet.
			jobCtx.finishedCondition = nil
		}
		active -= deleted
		if trackTerminatingPods(jobCtx.job) {
			*jobCtx.terminating += deleted
		}
		jobCtx.ready -= deletedReady
		manageJobErr = err
	} else {
		manageJobCalled := false
		if job.DeletionTimestamp == nil {
			active, manageJobErr = jm.manageJob(ctx, &job, jobCtx)
			manageJobCalled = true
		}
		// Evaluate success scenarios for Completions.
		complete := false
		if job.Spec.Completions == nil {
			// This type of job is complete when any pod exits with success.
			// Each pod is capable of
			// determining whether or not the entire Job is done.  Subsequent pods are
			// not expected to fail, but if they do, the failure is ignored.  Once any
			// pod succeeds, the controller waits for remaining pods to finish, and
			// then the job is complete.
			complete = jobCtx.succeeded > 0 && active == 0
		} else {
			// Job specifies a number of completions.  This type of job signals
			// success by having that number of successes.  Since we do not
			// start more pods than there are remaining completions, there should
			// not be any remaining active pods once this count is reached.
			complete = jobCtx.succeeded >= *job.Spec.Completions && active == 0
		}
		if complete {
			jobCtx.finishedCondition = jm.newSuccessCondition()
		} else if manageJobCalled {
			// Update the conditions / emit events only if manageJob was called in
			// this syncJob. Otherwise wait for the right syncJob call to make
			// updates.
			if jobSuspended(&job) {
				// Job can be in the suspended state only if it is NOT completed.
				var isUpdated bool
				job.Status.Conditions, isUpdated = ensureJobConditionStatus(job.Status.Conditions, batch.JobSuspended, v1.ConditionTrue, "JobSuspended", "Job suspended", jm.clock.Now())
				if isUpdated {
					suspendCondChanged = true
					jm.recorder.Event(&job, v1.EventTypeNormal, "Suspended", "Job suspended")
				}
			} else {
				// Job not suspended.
				var isUpdated bool
				job.Status.Conditions, isUpdated = ensureJobConditionStatus(job.Status.Conditions, batch.JobSuspended, v1.ConditionFalse, "JobResumed", "Job resumed", jm.clock.Now())
				if isUpdated {
					suspendCondChanged = true
					jm.recorder.Event(&job, v1.EventTypeNormal, "Resumed", "Job resumed")
					// Resumed jobs will always reset StartTime to current time. This is
					// done because the ActiveDeadlineSeconds timer shouldn't go off
					// whilst the Job is still suspended and resetting StartTime is
					// consistent with resuming a Job created in the suspended state.
					// (ActiveDeadlineSeconds is interpreted as the number of seconds a
					// Job is continuously active.)
					now := metav1.NewTime(jm.clock.Now())
					job.Status.StartTime = &now
				}
			}
		}
	}

	var terminating *int32
	needsStatusUpdate := suspendCondChanged || active != job.Status.Active || !ptr.Equal(&jobCtx.ready, job.Status.Ready)
	needsStatusUpdate = needsStatusUpdate || !ptr.Equal(job.Status.Terminating, terminating)
	job.Status.Active = active
	job.Status.Ready = &jobCtx.ready
	job.Status.Terminating = terminating
	err = jm.trackJobStatusAndRemoveFinalizers(ctx, jobCtx, needsStatusUpdate)
	if err != nil {
		return fmt.Errorf("tracking status: %w", err)
	}

	return manageJobErr
}

// deleteActivePods issues deletion for active Pods, preserving finalizers.
// This is done through DELETE calls that set deletion timestamps.
// The method trackJobStatusAndRemoveFinalizers removes the finalizers, after
// which the objects can actually be deleted.
// Returns number of successfully deleted ready pods and total number of successfully deleted pods.
func (jm *Controller) deleteActivePods(ctx context.Context, job *batch.Job, pods []*v1.Pod) (int32, int32, error) {
	errCh := make(chan error, len(pods))
	successfulDeletes := int32(len(pods))
	var deletedReady int32 = 0
	wg := sync.WaitGroup{}
	wg.Add(len(pods))
	for i := range pods {
		go func(pod *v1.Pod) {
			defer wg.Done()
			if err := jm.podControl.DeletePod(ctx, job.Namespace, pod.Name, job); err != nil && !apierrors.IsNotFound(err) {
				atomic.AddInt32(&successfulDeletes, -1)
				errCh <- err
				utilruntime.HandleError(err)
			}
			if podutil.IsPodReady(pod) {
				atomic.AddInt32(&deletedReady, 1)
			}
		}(pods[i])
	}
	wg.Wait()
	return deletedReady, successfulDeletes, errorFromChannel(errCh)
}

func nonIgnoredFailedPodsCount(jobCtx *syncJobCtx, failedPods []*v1.Pod) int {
	result := len(failedPods)
	if jobCtx.job.Spec.PodFailurePolicy != nil {
		for _, p := range failedPods {
			_, countFailed, _ := matchPodFailurePolicy(jobCtx.job.Spec.PodFailurePolicy, p)
			if !countFailed {
				result--
			}
		}
	}
	return result
}

// deleteJobPods deletes the pods, returns the number of successful removals of ready pods and total number of successful pod removals
// and any error.
func (jm *Controller) deleteJobPods(ctx context.Context, job *batch.Job, jobKey string, pods []*v1.Pod) (int32, int32, error) {
	errCh := make(chan error, len(pods))
	successfulDeletes := int32(len(pods))
	var deletedReady int32 = 0
	logger := klog.FromContext(ctx)

	failDelete := func(pod *v1.Pod, err error) {
		if !apierrors.IsNotFound(err) {
			logger.V(2).Info("Failed to delete Pod", "job", klog.KObj(job), "pod", klog.KObj(pod), "err", err)
			atomic.AddInt32(&successfulDeletes, -1)
			errCh <- err
			utilruntime.HandleError(err)
		}
	}

	wg := sync.WaitGroup{}
	wg.Add(len(pods))
	for i := range pods {
		go func(pod *v1.Pod) {
			defer wg.Done()
			if patch := removeTrackingFinalizerPatch(pod); patch != nil {
				if err := jm.podControl.PatchPod(ctx, pod.Namespace, pod.Name, patch); err != nil {
					failDelete(pod, fmt.Errorf("removing completion finalizer: %w", err))
					return
				}
			}
			if err := jm.podControl.DeletePod(ctx, job.Namespace, pod.Name, job); err != nil {
				failDelete(pod, err)
			}
			if podutil.IsPodReady(pod) {
				atomic.AddInt32(&deletedReady, 1)
			}
		}(pods[i])
	}
	wg.Wait()
	return deletedReady, successfulDeletes, errorFromChannel(errCh)
}

// trackJobStatusAndRemoveFinalizers does:
//  1. Add finished Pods to .status.uncountedTerminatedPods
//  2. Remove the finalizers from the Pods if they completed or were removed
//     or the job was removed.
//  3. Increment job counters for pods that no longer have a finalizer.
//  4. Add Complete condition if satisfied with current counters.
//
// It does this up to a limited number of Pods so that the size of .status
// doesn't grow too much and this sync doesn't starve other Jobs.
func (jm *Controller) trackJobStatusAndRemoveFinalizers(ctx context.Context, jobCtx *syncJobCtx, needsFlush bool) error {
	logger := klog.FromContext(ctx)

	isIndexed := isIndexedJob(jobCtx.job)
	var podsToRemoveFinalizer []*v1.Pod
	uncountedStatus := jobCtx.job.Status.UncountedTerminatedPods
	var newSucceededIndexes []int
	if isIndexed {
		// Sort to introduce completed Indexes in order.
		sort.Sort(byCompletionIndex(jobCtx.pods))
	}
	uidsWithFinalizer := make(sets.Set[types.UID], len(jobCtx.pods))
	for _, p := range jobCtx.pods {
		if hasJobTrackingFinalizer(p) {
			uidsWithFinalizer.Insert(p.UID)
		}
	}

	// Shallow copy, as it will only be used to detect changes in the counters.
	oldCounters := jobCtx.job.Status
	if cleanUncountedPodsWithoutFinalizers(&jobCtx.job.Status, uidsWithFinalizer) {
		needsFlush = true
	}
	podFailureCountByPolicyAction := map[string]int{}
	reachedMaxUncountedPods := false
	for _, pod := range jobCtx.pods {
		if !hasJobTrackingFinalizer(pod) {
			// This pod was processed in a previous sync.
			continue
		}
		considerPodFailed := isPodFailed(pod, jobCtx.job)
		if !canRemoveFinalizer(logger, jobCtx, pod, considerPodFailed) {
			continue
		}
		podsToRemoveFinalizer = append(podsToRemoveFinalizer, pod)
		if pod.Status.Phase == v1.PodSucceeded && !jobCtx.uncounted.failed.Has(pod.UID) {
			if isIndexed {
				// The completion index is enough to avoid recounting succeeded pods.
				// No need to track UIDs.
				ix := getCompletionIndex(pod.Annotations)
				if ix != unknownCompletionIndex && ix < int(*jobCtx.job.Spec.Completions) && !jobCtx.prevSucceededIndexes.has(ix) {
					newSucceededIndexes = append(newSucceededIndexes, ix)
					needsFlush = true
				}
			} else if !jobCtx.uncounted.succeeded.Has(pod.UID) {
				needsFlush = true
				uncountedStatus.Succeeded = append(uncountedStatus.Succeeded, pod.UID)
			}
		} else if considerPodFailed || (jobCtx.finishedCondition != nil && !isSuccessCriteriaMetCondition(jobCtx.finishedCondition)) {
			// When the job is considered finished, every non-terminated pod is considered failed.
			ix := getCompletionIndex(pod.Annotations)
			if !jobCtx.uncounted.failed.Has(pod.UID) && (!isIndexed || (ix != unknownCompletionIndex && ix < int(*jobCtx.job.Spec.Completions))) {
				if jobCtx.job.Spec.PodFailurePolicy != nil {
					_, countFailed, action := matchPodFailurePolicy(jobCtx.job.Spec.PodFailurePolicy, pod)
					if action != nil {
						podFailureCountByPolicyAction[string(*action)] += 1
					}
					if countFailed {
						needsFlush = true
						uncountedStatus.Failed = append(uncountedStatus.Failed, pod.UID)
					}
				} else {
					needsFlush = true
					uncountedStatus.Failed = append(uncountedStatus.Failed, pod.UID)
				}
			}
		}
		if len(newSucceededIndexes)+len(uncountedStatus.Succeeded)+len(uncountedStatus.Failed) >= MaxUncountedPods {
			// The controller added enough Pods already to .status.uncountedTerminatedPods
			// We stop counting pods and removing finalizers here to:
			// 1. Ensure that the UIDs representation are under 20 KB.
			// 2. Cap the number of finalizer removals so that syncing of big Jobs
			//    doesn't starve smaller ones.
			//
			// The job will be synced again because the Job status and Pod updates
			// will put the Job back to the work queue.
			reachedMaxUncountedPods = true
			break
		}
	}
	if isIndexed {
		jobCtx.succeededIndexes = jobCtx.succeededIndexes.withOrderedIndexes(newSucceededIndexes)
		succeededIndexesStr := jobCtx.succeededIndexes.String()
		if succeededIndexesStr != jobCtx.job.Status.CompletedIndexes {
			needsFlush = true
		}
		jobCtx.job.Status.Succeeded = int32(jobCtx.succeededIndexes.total())
		jobCtx.job.Status.CompletedIndexes = succeededIndexesStr
		var failedIndexesStr *string
		if jobCtx.failedIndexes != nil {
			failedIndexesStr = ptr.To(jobCtx.failedIndexes.String())
		}
		if !ptr.Equal(jobCtx.job.Status.FailedIndexes, failedIndexesStr) {
			jobCtx.job.Status.FailedIndexes = failedIndexesStr
			needsFlush = true
		}
	}
	// Evaluate jobCtx.finishedCondition and transform FailureTarget to Failed.
	if jobCtx.finishedCondition != nil && jobCtx.finishedCondition.Type == batch.JobFailureTarget {

		// Append the interim FailureTarget condition to update the job status with before finalizers are removed.
		jobCtx.job.Status.Conditions = append(jobCtx.job.Status.Conditions, *jobCtx.finishedCondition)
		needsFlush = true

		// Prepare the final Failed condition to update the job status with after the finalizers are removed.
		// It is also used in the enactJobFinished function for reporting.
		jobCtx.finishedCondition = newFailedConditionForFailureTarget(jobCtx.finishedCondition, jm.clock.Now())
	}
	// Evaluate jobCtx.finishedCondition and transform SuccessCriteriaMet to Complete.
	if isSuccessCriteriaMetCondition(jobCtx.finishedCondition) {
		// Append the interim SuccessCriteriaMet condition to update the job status with before finalizers are removed.
		if hasSuccessCriteriaMetCondition(jobCtx.job) == nil {
			jobCtx.job.Status.Conditions = append(jobCtx.job.Status.Conditions, *jobCtx.finishedCondition)
			needsFlush = true
		}

		// Prepare the final Complete condition to update the job status with after the finalizers are removed.
		// It is also used in the enactJobFinished function for reporting.
		jobCtx.finishedCondition = newCondition(batch.JobComplete, v1.ConditionTrue, jobCtx.finishedCondition.Reason, jobCtx.finishedCondition.Message, jm.clock.Now())
	}
	var err error
	if jobCtx.job, needsFlush, err = jm.flushUncountedAndRemoveFinalizers(ctx, jobCtx, podsToRemoveFinalizer, uidsWithFinalizer, &oldCounters, podFailureCountByPolicyAction, needsFlush); err != nil {
		return err
	}
	jobFinished := !reachedMaxUncountedPods && jm.enactJobFinished(logger, jobCtx)
	if jobFinished {
		needsFlush = true
	}
	if needsFlush {
		if _, err := jm.updateStatusHandler(ctx, jobCtx.job); err != nil {
			return fmt.Errorf("removing uncounted pods from status: %w", err)
		}
		if jobFinished {
			jm.recordJobFinished(logger, jobCtx.job, jobCtx.finishedCondition)
		}
	}
	return nil
}

// canRemoveFinalizer determines if the pod's finalizer can be safely removed.
// The finalizer can be removed when:
//   - the entire Job is terminating; or
//   - the pod's index is succeeded; or
//   - the Pod is considered failed, unless it's removal is delayed for the
//     purpose of transferring the JobIndexFailureCount annotations to the
//     replacement pod. the entire Job is terminating the finalizer can be
//     removed unconditionally; or
//   - the Job met successPolicy.
func canRemoveFinalizer(logger klog.Logger, jobCtx *syncJobCtx, pod *v1.Pod, considerPodFailed bool) bool {
	if jobCtx.job.DeletionTimestamp != nil || jobCtx.finishedCondition != nil || pod.Status.Phase == v1.PodSucceeded {
		return true
	}
	if !considerPodFailed {
		return false
	}
	if hasBackoffLimitPerIndex(jobCtx.job) {
		if index := getCompletionIndex(pod.Annotations); index != unknownCompletionIndex {
			if p, ok := jobCtx.podsWithDelayedDeletionPerIndex[index]; ok && p.UID == pod.UID {
				logger.V(3).Info("Delaying pod finalizer removal to await for pod recreation within the index", "pod", klog.KObj(pod))
				return false
			}
		}
	}
	return true
}

// flushUncountedAndRemoveFinalizers does:
//  1. flush the Job status that might include new uncounted Pod UIDs.
//     Also flush the interim FailureTarget and SuccessCriteriaMet conditions if present.
//  2. perform the removal of finalizers from Pods which are in the uncounted
//     lists.
//  3. update the counters based on the Pods for which it successfully removed
//     the finalizers.
//  4. (if not all removals succeeded) flush Job status again.
//
// Returns whether there are pending changes in the Job status that need to be
// flushed in subsequent calls.
func (jm *Controller) flushUncountedAndRemoveFinalizers(ctx context.Context, jobCtx *syncJobCtx, podsToRemoveFinalizer []*v1.Pod, uidsWithFinalizer sets.Set[types.UID], oldCounters *batch.JobStatus, podFailureCountByPolicyAction map[string]int, needsFlush bool) (*batch.Job, bool, error) {
	logger := klog.FromContext(ctx)
	var err error
	if needsFlush {
		if jobCtx.job, err = jm.updateStatusHandler(ctx, jobCtx.job); err != nil {
			return jobCtx.job, needsFlush, fmt.Errorf("adding uncounted pods to status: %w", err)
		}

		err = jm.podBackoffStore.updateBackoffRecord(jobCtx.newBackoffRecord)

		if err != nil {
			// this error might undercount the backoff.
			// re-syncing from the current state might not help to recover
			// the backoff information
			logger.Error(err, "Backoff update failed")
		}

		// Shallow copy, as it will only be used to detect changes in the counters.
		*oldCounters = jobCtx.job.Status
		needsFlush = false
	}

	if err != nil {
		return jobCtx.job, needsFlush, fmt.Errorf("getting job key: %w", err)
	}
	var rmErr error
	if len(podsToRemoveFinalizer) > 0 {
		var rmSucceded []bool
		rmSucceded, rmErr = jm.removeTrackingFinalizerFromPods(ctx, podsToRemoveFinalizer)
		for i, p := range podsToRemoveFinalizer {
			if rmSucceded[i] {
				uidsWithFinalizer.Delete(p.UID)
			}
		}
	}
	// Failed to remove some finalizers. Attempt to update the status with the
	// partial progress.
	if cleanUncountedPodsWithoutFinalizers(&jobCtx.job.Status, uidsWithFinalizer) {
		needsFlush = true
	}
	if rmErr != nil && needsFlush {
		if job, err := jm.updateStatusHandler(ctx, jobCtx.job); err != nil {
			return job, needsFlush, fmt.Errorf("removing uncounted pods from status: %w", err)
		}
	}
	return jobCtx.job, needsFlush, rmErr
}

// cleanUncountedPodsWithoutFinalizers removes the Pod UIDs from
// .status.uncountedTerminatedPods for which the finalizer was successfully
// removed and increments the corresponding status counters.
// Returns whether there was any status change.
func cleanUncountedPodsWithoutFinalizers(status *batch.JobStatus, uidsWithFinalizer sets.Set[types.UID]) bool {
	updated := false
	uncountedStatus := status.UncountedTerminatedPods
	newUncounted := filterInUncountedUIDs(uncountedStatus.Succeeded, uidsWithFinalizer)
	if len(newUncounted) != len(uncountedStatus.Succeeded) {
		updated = true
		status.Succeeded += int32(len(uncountedStatus.Succeeded) - len(newUncounted))
		uncountedStatus.Succeeded = newUncounted
	}
	newUncounted = filterInUncountedUIDs(uncountedStatus.Failed, uidsWithFinalizer)
	if len(newUncounted) != len(uncountedStatus.Failed) {
		updated = true
		status.Failed += int32(len(uncountedStatus.Failed) - len(newUncounted))
		uncountedStatus.Failed = newUncounted
	}
	return updated
}

// removeTrackingFinalizerFromPods removes tracking finalizers from Pods and
// returns an array of booleans where the i-th value is true if the finalizer
// of the i-th Pod was successfully removed (if the pod was deleted when this
// function was called, it's considered as the finalizer was removed successfully).
func (jm *Controller) removeTrackingFinalizerFromPods(ctx context.Context, pods []*v1.Pod) ([]bool, error) {
	errCh := make(chan error, len(pods))
	succeeded := make([]bool, len(pods))
	wg := sync.WaitGroup{}
	wg.Add(len(pods))
	for i := range pods {
		go func(i int) {
			pod := pods[i]
			defer wg.Done()
			if patch := removeTrackingFinalizerPatch(pod); patch != nil {
				if err := jm.podControl.PatchPod(ctx, pod.Namespace, pod.Name, patch); err != nil {
					if !apierrors.IsNotFound(err) {
						errCh <- err
						utilruntime.HandleError(fmt.Errorf("removing tracking finalizer: %w", err))
						return
					}
				}
				succeeded[i] = true
			}
		}(i)
	}
	wg.Wait()

	return succeeded, errorFromChannel(errCh)
}

// enactJobFinished adds the Complete or Failed condition and records events.
// Returns whether the Job was considered finished.
func (jm *Controller) enactJobFinished(logger klog.Logger, jobCtx *syncJobCtx) bool {
	if jobCtx.finishedCondition == nil {
		return false
	}
	job := jobCtx.job
	if uncounted := job.Status.UncountedTerminatedPods; uncounted != nil {
		if count := len(uncounted.Succeeded) + len(uncounted.Failed); count > 0 {
			logger.V(4).Info("Delaying marking the Job as finished, because there are still uncounted pod(s)", "job", klog.KObj(job), "condition", jobCtx.finishedCondition.Type, "count", count)
			return false
		}
	}
	if delayTerminalCondition() {
		if *jobCtx.terminating > 0 {
			logger.V(4).Info("Delaying marking the Job as finished, because there are still terminating pod(s)", "job", klog.KObj(job), "condition", jobCtx.finishedCondition.Type, "count", *jobCtx.terminating)
			return false
		}
	}
	finishedCond := jobCtx.finishedCondition
	job.Status.Conditions, _ = ensureJobConditionStatus(job.Status.Conditions, finishedCond.Type, finishedCond.Status, finishedCond.Reason, finishedCond.Message, jm.clock.Now())
	if finishedCond.Type == batch.JobComplete {
		job.Status.CompletionTime = &finishedCond.LastTransitionTime
	}
	return true
}

// recordJobFinished records events and a concise log entry for a finished job.
func (jm *Controller) recordJobFinished(logger klog.Logger, job *batch.Job, finishedCond *batch.JobCondition) bool {
	if finishedCond.Type == batch.JobComplete {
		if job.Spec.Completions != nil && job.Status.Succeeded > *job.Spec.Completions {
			jm.recorder.Event(job, v1.EventTypeWarning, "TooManySucceededPods", "Too many succeeded pods running after completion count reached")
		}
		jm.recorder.Event(job, v1.EventTypeNormal, "Completed", "Job completed")
		logger.Info("Job completed", "job", klog.KObj(job), "reason", finishedCond.Reason, "succeeded", job.Status.Succeeded, "failed", job.Status.Failed)
	} else {
		jm.recorder.Event(job, v1.EventTypeWarning, finishedCond.Reason, finishedCond.Message)
		logger.Info("Job failed", "job", klog.KObj(job), "reason", finishedCond.Reason, "message", finishedCond.Message, "succeeded", job.Status.Succeeded, "failed", job.Status.Failed)
	}
	return true
}

func filterInUncountedUIDs(uncounted []types.UID, include sets.Set[types.UID]) []types.UID {
	var newUncounted []types.UID
	for _, uid := range uncounted {
		if include.Has(uid) {
			newUncounted = append(newUncounted, uid)
		}
	}
	return newUncounted
}

// newFailedConditionForFailureTarget creates a job Failed condition based on
// the interim FailureTarget condition.
func newFailedConditionForFailureTarget(condition *batch.JobCondition, now time.Time) *batch.JobCondition {
	return newCondition(batch.JobFailed, v1.ConditionTrue, condition.Reason, condition.Message, now)
}

// pastBackoffLimitOnFailure checks if container restartCounts sum exceeds BackoffLimit
// this method applies only to pods with restartPolicy == OnFailure
func pastBackoffLimitOnFailure(job *batch.Job, pods []*v1.Pod) bool {
	if job.Spec.Template.Spec.RestartPolicy != v1.RestartPolicyOnFailure {
		return false
	}
	result := int32(0)
	for i := range pods {
		po := pods[i]
		if po.Status.Phase == v1.PodRunning || po.Status.Phase == v1.PodPending {
			for j := range po.Status.InitContainerStatuses {
				stat := po.Status.InitContainerStatuses[j]
				result += stat.RestartCount
			}
			for j := range po.Status.ContainerStatuses {
				stat := po.Status.ContainerStatuses[j]
				result += stat.RestartCount
			}
		}
	}
	if *job.Spec.BackoffLimit == 0 {
		return result > 0
	}
	return result >= *job.Spec.BackoffLimit
}

// pastActiveDeadline checks if job has ActiveDeadlineSeconds field set and if
// it is exceeded. If the job is currently suspended, the function will always
// return false.
func (jm *Controller) pastActiveDeadline(job *batch.Job) bool {
	if job.Spec.ActiveDeadlineSeconds == nil || job.Status.StartTime == nil || jobSuspended(job) {
		return false
	}
	duration := jm.clock.Since(job.Status.StartTime.Time)
	allowedDuration := time.Duration(*job.Spec.ActiveDeadlineSeconds) * time.Second
	return duration >= allowedDuration
}

func newCondition(conditionType batch.JobConditionType, status v1.ConditionStatus, reason, message string, now time.Time) *batch.JobCondition {
	return &batch.JobCondition{
		Type:               conditionType,
		Status:             status,
		LastProbeTime:      metav1.NewTime(now),
		LastTransitionTime: metav1.NewTime(now),
		Reason:             reason,
		Message:            message,
	}
}

// getFailJobMessage returns a job failure message if the job should fail with the current counters
func getFailJobMessage(job *batch.Job, pods []*v1.Pod) *string {
	if job.Spec.PodFailurePolicy == nil {
		return nil
	}
	for _, p := range pods {
		if isPodFailed(p, job) {
			jobFailureMessage, _, _ := matchPodFailurePolicy(job.Spec.PodFailurePolicy, p)
			if jobFailureMessage != nil {
				return jobFailureMessage
			}
		}
	}
	return nil
}

// getNewFinishedPods returns the list of newly succeeded and failed pods that are not accounted
// in the job status. The list of failed pods can be affected by the podFailurePolicy.
func getNewFinishedPods(jobCtx *syncJobCtx) (succeededPods, failedPods []*v1.Pod) {
	succeededPods = getValidPodsWithFilter(jobCtx, jobCtx.uncounted.Succeeded(), func(p *v1.Pod) bool {
		return p.Status.Phase == v1.PodSucceeded
	})
	failedPods = getValidPodsWithFilter(jobCtx, jobCtx.uncounted.Failed(), func(p *v1.Pod) bool {
		return isPodFailed(p, jobCtx.job)
	})
	return succeededPods, failedPods
}

// jobSuspended returns whether a Job is suspended while taking the feature
// gate into account.
func jobSuspended(job *batch.Job) bool {
	return job.Spec.Suspend != nil && *job.Spec.Suspend
}

// manageJob is the core method responsible for managing the number of running
// pods according to what is specified in the job.Spec.
// Respects back-off; does not create new pods if the back-off time has not passed
// Does NOT modify <activePods>.
func (jm *Controller) manageJob(ctx context.Context, job *batch.Job, jobCtx *syncJobCtx) (int32, error) {
	logger := klog.FromContext(ctx)
	active := int32(len(jobCtx.activePods))
	parallelism := *job.Spec.Parallelism
	jobKey, err := controller.KeyFunc(job)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("Couldn't get key for job %#v: %v", job, err))
		return 0, nil
	}

	if jobSuspended(job) {
		logger.Info("Deleting active pods for suspended job", "job", klog.KObj(job), "active", active)
		podsToDelete := activePodsForRemoval(job, jobCtx.activePods, int(active))
		removedReady, removed, err := jm.deleteJobPods(ctx, job, jobKey, podsToDelete)
		active -= removed
		if trackTerminatingPods(job) {
			*jobCtx.terminating += removed
		}
		jobCtx.ready -= removedReady
		return active, err
	}

	wantActive := int32(0)
	if job.Spec.Completions == nil {
		// Job does not specify a number of completions.  Therefore, number active
		// should be equal to parallelism, unless the job has seen at least
		// once success, in which leave whatever is running, running.
		if jobCtx.succeeded > 0 {
			wantActive = active
		} else {
			wantActive = parallelism
		}
	} else {
		// Job specifies a specific number of completions.  Therefore, number
		// active should not ever exceed number of remaining completions.
		wantActive = *job.Spec.Completions - jobCtx.succeeded
		if wantActive > parallelism {
			wantActive = parallelism
		}
		if wantActive < 0 {
			wantActive = 0
		}
	}

	rmAtLeast := active - wantActive
	if rmAtLeast < 0 {
		rmAtLeast = 0
	}
	podsToDelete := activePodsForRemoval(job, jobCtx.activePods, int(rmAtLeast))
	if len(podsToDelete) > MaxPodCreateDeletePerSync {
		podsToDelete = podsToDelete[:MaxPodCreateDeletePerSync]
	}
	if len(podsToDelete) > 0 {
		logger.Info("Deleting excess pods for job", "job", klog.KObj(job), "deleteCount", len(podsToDelete), "targetActive", wantActive, "currentActive", active)
		removedReady, removed, err := jm.deleteJobPods(ctx, job, jobKey, podsToDelete)
		active -= removed
		if trackTerminatingPods(job) {
			*jobCtx.terminating += removed
		}
		jobCtx.ready -= removedReady
		// While it is possible for a Job to require both pod creations and
		// deletions at the same time (e.g. indexed Jobs with repeated indexes), we
		// restrict ourselves to either just pod deletion or pod creation in any
		// given sync cycle. Of these two, pod deletion takes precedence.
		return active, err
	}

	var terminating int32 = 0
	if onlyReplaceFailedPods(jobCtx.job) {
		// When onlyReplaceFailedPods=true, then also trackTerminatingPods=true,
		// and so we can use the value.
		terminating = *jobCtx.terminating
	}
	if diff := wantActive - terminating - active; diff > 0 {
		var remainingTime time.Duration
		if !hasBackoffLimitPerIndex(job) {
			// we compute the global remaining time for pod creation when backoffLimitPerIndex is not used
			remainingTime = jobCtx.newBackoffRecord.getRemainingTime(jm.clock, DefaultJobPodFailureBackOff, MaxJobPodFailureBackOff)
		}
		if remainingTime > 0 {
			logger.Info("Delaying pod creation for job due to backoff", "job", klog.KObj(job), "delay", remainingTime)
			if err := jm.enqueueSyncJobWithDelay(ctx, logger, job, remainingTime); err != nil {
				return 0, err
			}
			return 0, nil
		}
		if diff > int32(MaxPodCreateDeletePerSync) {
			diff = int32(MaxPodCreateDeletePerSync)
		}

		var indexesToAdd []int
		if isIndexedJob(job) {
			indexesToAdd = firstPendingIndexes(jobCtx, int(diff), int(*job.Spec.Completions))
			if hasBackoffLimitPerIndex(job) {
				indexesToAdd, remainingTime = jm.getPodCreationInfoForIndependentIndexes(logger, indexesToAdd, jobCtx.podsWithDelayedDeletionPerIndex)
				if remainingTime > 0 {
					logger.Info("Delaying indexed pod creation for job due to backoff", "job", klog.KObj(job), "delay", remainingTime)
					if err := jm.enqueueSyncJobWithDelay(ctx, logger, job, remainingTime); err != nil {
						return 0, err
					}
					return 0, nil
				}
			}
			diff = int32(len(indexesToAdd))
		}

		errCh := make(chan error, diff)
		logger.Info("Creating pods for job", "job", klog.KObj(job), "createCount", diff, "targetActive", wantActive, "currentActive", active)

		wait := sync.WaitGroup{}

		active += diff

		podTemplate := job.Spec.Template.DeepCopy()
		if isIndexedJob(job) {
			addCompletionIndexEnvVariables(podTemplate)
		}
		podTemplate.Finalizers = appendJobCompletionFinalizerIfNotFound(podTemplate.Finalizers)

		// Counters for pod creation status (used by the job_pods_creation_total metric)
		var creationsSucceeded, creationsFailed int32 = 0, 0

		// Batch the pod creates. Batch sizes start at SlowStartInitialBatchSize
		// and double with each successful iteration in a kind of "slow start".
		// This handles attempts to start large numbers of pods that would
		// likely all fail with the same error. For example a project with a
		// low quota that attempts to create a large number of pods will be
		// prevented from spamming the API service with the pod create requests
		// after one of its pods fails.  Conveniently, this also prevents the
		// event spam that those failures would generate.
		for batchSize := min(diff, int32(controller.SlowStartInitialBatchSize)); diff > 0; batchSize = min(2*batchSize, diff) {
			errorCount := len(errCh)
			wait.Add(int(batchSize))
			for i := int32(0); i < batchSize; i++ {
				completionIndex := unknownCompletionIndex
				if len(indexesToAdd) > 0 {
					completionIndex = indexesToAdd[0]
					indexesToAdd = indexesToAdd[1:]
				}
				go func() {
					template := podTemplate
					generateName := ""
					if completionIndex != unknownCompletionIndex {
						template = podTemplate.DeepCopy()
						addCompletionIndexAnnotation(template, completionIndex)

						template.Spec.Hostname = fmt.Sprintf("%s-%d", job.Name, completionIndex)
						generateName = podGenerateNameWithIndex(job.Name, completionIndex)
						if hasBackoffLimitPerIndex(job) {
							addIndexFailureCountAnnotation(logger, template, job, jobCtx.podsWithDelayedDeletionPerIndex[completionIndex])
						}
					}
					defer wait.Done()
					err := jm.podControl.CreatePodsWithGenerateName(ctx, job.Namespace, template, job, metav1.NewControllerRef(job, controllerKind), generateName)
					if err != nil {
						if apierrors.HasStatusCause(err, v1.NamespaceTerminatingCause) {
							// If the namespace is being torn down, we can safely ignore
							// this error since all subsequent creations will fail.
							return
						}
					}
					if err != nil {
						defer utilruntime.HandleError(err)
						// Decrement the expected number of creates because the informer won't observe this pod
						logger.V(2).Info("Failed creation, decrementing expectations", "job", klog.KObj(job))
						atomic.AddInt32(&active, -1)
						errCh <- err
						atomic.AddInt32(&creationsFailed, 1)
					}
					atomic.AddInt32(&creationsSucceeded, 1)
				}()
			}
			wait.Wait()
			// any skipped pods that we never attempted to start shouldn't be expected.
			skippedPods := diff - batchSize
			if errorCount < len(errCh) && skippedPods > 0 {
				logger.V(2).Info("Slow-start failure. Skipping creating pods, decrementing expectations", "skippedCount", skippedPods, "job", klog.KObj(job))
				active -= skippedPods
				// The skipped pods will be retried later. The next controller resync will
				// retry the slow start process.
				break
			}
			diff -= batchSize
		}
		return active, errorFromChannel(errCh)
	}

	return active, nil
}

// getPodCreationInfoForIndependentIndexes returns a sub-list of all indexes
// to create that contains those which can be already created. In case no indexes
// are ready to create pods, it returns the lowest remaining time to create pods
// out of all indexes.
func (jm *Controller) getPodCreationInfoForIndependentIndexes(logger klog.Logger, indexesToAdd []int, podsWithDelayedDeletionPerIndex map[int]*v1.Pod) ([]int, time.Duration) {
	var indexesToAddNow []int
	var minRemainingTimePerIndex *time.Duration
	for _, indexToAdd := range indexesToAdd {
		if remainingTimePerIndex := getRemainingTimePerIndex(logger, jm.clock, DefaultJobPodFailureBackOff, MaxJobPodFailureBackOff, podsWithDelayedDeletionPerIndex[indexToAdd]); remainingTimePerIndex == 0 {
			indexesToAddNow = append(indexesToAddNow, indexToAdd)
		} else if minRemainingTimePerIndex == nil || remainingTimePerIndex < *minRemainingTimePerIndex {
			minRemainingTimePerIndex = &remainingTimePerIndex
		}
	}
	if len(indexesToAddNow) > 0 {
		return indexesToAddNow, 0
	}
	return indexesToAddNow, ptr.Deref(minRemainingTimePerIndex, 0)
}

// activePodsForRemoval returns Pods that should be removed because there
// are too many pods running or, if this is an indexed job, there are repeated
// indexes or invalid indexes or some pods don't have indexes.
// Sorts candidate pods in the order such that not-ready < ready, unscheduled
// < scheduled, and pending < running. This ensures that we delete pods
// in the earlier stages whenever possible.
func activePodsForRemoval(job *batch.Job, pods []*v1.Pod, rmAtLeast int) []*v1.Pod {
	var rm, left []*v1.Pod

	if isIndexedJob(job) {
		rm = make([]*v1.Pod, 0, rmAtLeast)
		left = make([]*v1.Pod, 0, len(pods)-rmAtLeast)
		rm, left = appendDuplicatedIndexPodsForRemoval(rm, left, pods, int(*job.Spec.Completions))
	} else {
		left = pods
	}

	if len(rm) < rmAtLeast {
		sort.Sort(controller.ActivePods(left))
		rm = append(rm, left[:rmAtLeast-len(rm)]...)
	}
	return rm
}

// updateJobStatus calls the API to update the job status.
func (jm *Controller) updateJobStatus(ctx context.Context, job *batch.Job) (*batch.Job, error) {
	return jm.kubeClient.BatchV1().Jobs(job.Namespace).UpdateStatus(ctx, job, metav1.UpdateOptions{})
}

func (jm *Controller) patchJob(ctx context.Context, job *batch.Job, data []byte) error {
	_, err := jm.kubeClient.BatchV1().Jobs(job.Namespace).Patch(
		ctx, job.Name, types.StrategicMergePatchType, data, metav1.PatchOptions{})
	return err
}

// getValidPodsWithFilter returns the valid pods that pass the filter.
// Pods are valid if they have a finalizer or in uncounted set
// and, for Indexed Jobs, a valid completion index.
func getValidPodsWithFilter(jobCtx *syncJobCtx, uncounted sets.Set[types.UID], filter func(*v1.Pod) bool) []*v1.Pod {
	var result []*v1.Pod
	for _, p := range jobCtx.pods {
		// Pods that don't have a completion finalizer are in the uncounted set or
		// have already been accounted for in the Job status.
		if !hasJobTrackingFinalizer(p) || uncounted.Has(p.UID) {
			continue
		}
		if isIndexedJob(jobCtx.job) {
			idx := getCompletionIndex(p.Annotations)
			if idx == unknownCompletionIndex || idx >= int(*jobCtx.job.Spec.Completions) {
				continue
			}
		}
		if filter(p) {
			result = append(result, p)
		}
	}
	return result
}

func appendJobCompletionFinalizerIfNotFound(finalizers []string) []string {
	for _, fin := range finalizers {
		if fin == batch.JobTrackingFinalizer {
			return finalizers
		}
	}
	return append(finalizers, batch.JobTrackingFinalizer)
}

func removeTrackingFinalizerPatch(pod *v1.Pod) []byte {
	if !hasJobTrackingFinalizer(pod) {
		return nil
	}
	patch := map[string]interface{}{
		"metadata": map[string]interface{}{
			"$deleteFromPrimitiveList/finalizers": []string{batch.JobTrackingFinalizer},
		},
	}
	patchBytes, _ := json.Marshal(patch)
	return patchBytes
}

type uncountedTerminatedPods struct {
	succeeded sets.Set[types.UID]
	failed    sets.Set[types.UID]
}

func newUncountedTerminatedPods(in batch.UncountedTerminatedPods) *uncountedTerminatedPods {
	return &uncountedTerminatedPods{
		succeeded: sets.New(in.Succeeded...),
		failed:    sets.New(in.Failed...),
	}
}

func (u *uncountedTerminatedPods) Succeeded() sets.Set[types.UID] {
	if u == nil {
		return nil
	}
	return u.succeeded
}

func (u *uncountedTerminatedPods) Failed() sets.Set[types.UID] {
	if u == nil {
		return nil
	}
	return u.failed
}

func errorFromChannel(errCh <-chan error) error {
	select {
	case err := <-errCh:
		return err
	default:
	}
	return nil
}
