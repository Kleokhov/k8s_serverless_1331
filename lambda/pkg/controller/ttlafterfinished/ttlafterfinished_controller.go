/*
Copyright 2018 The Kubernetes Authors.

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

package ttlafterfinished

import (
	"context"
	"fmt"
	"strings"
	"time"

	"lambda/pkg/controller/awsstore"

	batch "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientset "k8s.io/client-go/kubernetes"
	v1core "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog/v2"
	"k8s.io/kubectl/pkg/scheme"
	jobutil "k8s.io/kubernetes/pkg/controller/job/util"
	"k8s.io/kubernetes/pkg/controller/ttlafterfinished/metrics"
	"k8s.io/utils/clock"
)

// Controller checks finished Jobs with TTLs and deletes them once they expire.
// In the serverless mode, cleanup requests arrive via SQS and are handled by
// RunOnce without resident workers or event handlers.
type Controller struct {
	client   clientset.Interface
	recorder record.EventRecorder
	queue    awsstore.SQSQueue

	queueBatchSize         int32
	queueVisibilityTimeout time.Duration

	clock clock.Clock
}

const (
	DefaultQueueBatchSize         int32         = 10
	DefaultQueueVisibilityTimeout time.Duration = 30 * time.Second
)

type Option func(*Controller)

func WithQueueBatchSize(size int32) Option {
	return func(tc *Controller) {
		if size > 0 {
			tc.queueBatchSize = size
		}
	}
}

func WithQueueVisibilityTimeout(d time.Duration) Option {
	return func(tc *Controller) {
		if d >= 0 {
			tc.queueVisibilityTimeout = d
		}
	}
}

type Result struct {
	JobsDequeued int `json:"jobsDequeued"`
	JobsDeleted  int `json:"jobsDeleted"`
	JobsRequeued int `json:"jobsRequeued"`
	JobsSkipped  int `json:"jobsSkipped"`
	JobsFailed   int `json:"jobsFailed"`
}

type jobOutcome int

const (
	jobOutcomeSkipped jobOutcome = iota
	jobOutcomeRequeued
	jobOutcomeDeleted
)

// NewLambdaController creates a serverless TTL-after-finished controller.
func NewLambdaController(queue awsstore.SQSQueue, client clientset.Interface, opts ...Option) (*Controller, error) {
	if client == nil {
		return nil, fmt.Errorf("nil kube client")
	}
	if queue == nil {
		return nil, fmt.Errorf("nil ttl queue")
	}

	eventBroadcaster := record.NewBroadcaster(record.WithContext(context.Background()))
	eventBroadcaster.StartStructuredLogging(3)
	eventBroadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: client.CoreV1().Events("")})

	metrics.Register()

	tc := &Controller{
		client:                 client,
		recorder:               eventBroadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: "ttl-after-finished-controller"}),
		queue:                  queue,
		queueBatchSize:         DefaultQueueBatchSize,
		queueVisibilityTimeout: DefaultQueueVisibilityTimeout,
		clock:                  clock.RealClock{},
	}

	for _, opt := range opts {
		opt(tc)
	}

	return tc, nil
}

func (tc *Controller) enqueueAfter(ctx context.Context, key string, after time.Duration) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return fmt.Errorf("empty ttl job key")
	}
	if after < 0 {
		after = 0
	}
	return tc.queue.EnqueueAfter(ctx, key, after)
}

// RunOnce dequeues a batch of job keys from SQS, checks TTL expiry, and either
// deletes expired Jobs or re-enqueues them for later processing.
func (tc *Controller) RunOnce(ctx context.Context) (Result, error) {
	logger := klog.FromContext(ctx)

	items, err := tc.queue.Dequeue(ctx, tc.queueBatchSize, tc.queueVisibilityTimeout)
	if err != nil {
		return Result{}, fmt.Errorf("dequeue ttl jobs: %w", err)
	}

	result := Result{JobsDequeued: len(items)}
	var errs []error

	for _, item := range items {
		key := strings.TrimSpace(item.Body)
		if key == "" {
			logger.V(2).Info("Skipping empty ttl queue message")
			if delErr := tc.queue.Delete(ctx, item.ReceiptHandle); delErr != nil {
				errs = append(errs, fmt.Errorf("delete empty ttl queue item: %w", delErr))
			}
			result.JobsDequeued--
			continue
		}

		outcome, processErr := tc.processJob(ctx, key)
		if processErr != nil {
			logger.Error(processErr, "Failed to process ttl cleanup job", "key", key)
			errs = append(errs, fmt.Errorf("process ttl job %q: %w", key, processErr))
			result.JobsFailed++
			continue
		}

		switch outcome {
		case jobOutcomeDeleted:
			result.JobsDeleted++
		case jobOutcomeRequeued:
			result.JobsRequeued++
		default:
			result.JobsSkipped++
		}

		if delErr := tc.queue.Delete(ctx, item.ReceiptHandle); delErr != nil {
			errs = append(errs, fmt.Errorf("delete ttl queue item for job %q: %w", key, delErr))
		}
	}

	logger.Info("TTL-after-finished invocation completed",
		"jobsDequeued", result.JobsDequeued,
		"jobsDeleted", result.JobsDeleted,
		"jobsRequeued", result.JobsRequeued,
		"jobsSkipped", result.JobsSkipped,
		"jobsFailed", result.JobsFailed,
	)

	return result, joinErrors(errs)
}

// ProcessItems processes pre-delivered queue items (from an SQS event trigger) and
// returns the message IDs of items that failed and should be retried.
func (tc *Controller) ProcessItems(ctx context.Context, items []awsstore.QueuedItem) (Result, []string) {
	logger := klog.FromContext(ctx)
	result := Result{JobsDequeued: len(items)}
	var failedIDs []string

	for _, item := range items {
		key := strings.TrimSpace(item.Body)
		if key == "" {
			logger.V(2).Info("Skipping empty ttl queue message")
			result.JobsDequeued--
			continue
		}
		outcome, processErr := tc.processJob(ctx, key)
		if processErr != nil {
			logger.Error(processErr, "Failed to process ttl cleanup job", "key", key)
			result.JobsFailed++
			failedIDs = append(failedIDs, item.MessageID)
			continue
		}
		switch outcome {
		case jobOutcomeDeleted:
			result.JobsDeleted++
		case jobOutcomeRequeued:
			result.JobsRequeued++
		default:
			result.JobsSkipped++
		}
	}
	return result, failedIDs
}

// processJob checks a Job's state and TTL and deletes it when its TTL expires.
// If the TTL has not expired yet, the Job is re-enqueued to be checked later.
func (tc *Controller) processJob(ctx context.Context, key string) (jobOutcome, error) {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return jobOutcomeSkipped, err
	}

	job, err := tc.client.BatchV1().Jobs(namespace).Get(ctx, name, metav1.GetOptions{})
	logger := klog.FromContext(ctx)
	logger.V(4).Info("Checking if Job is ready for ttl cleanup", "job", klog.KRef(namespace, name))

	if errors.IsNotFound(err) {
		return jobOutcomeSkipped, nil
	}
	if err != nil {
		return jobOutcomeSkipped, err
	}

	expiredAt, requeued, err := tc.processTTL(ctx, logger, job)
	if err != nil {
		return jobOutcomeSkipped, err
	}
	if requeued {
		return jobOutcomeRequeued, nil
	}
	if expiredAt == nil {
		return jobOutcomeSkipped, nil
	}

	fresh, err := tc.client.BatchV1().Jobs(namespace).Get(ctx, name, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		return jobOutcomeSkipped, nil
	}
	if err != nil {
		return jobOutcomeSkipped, err
	}

	expiredAt, requeued, err = tc.processTTL(ctx, logger, fresh)
	if err != nil {
		return jobOutcomeSkipped, err
	}
	if requeued {
		return jobOutcomeRequeued, nil
	}
	if expiredAt == nil {
		return jobOutcomeSkipped, nil
	}

	policy := metav1.DeletePropagationForeground
	options := metav1.DeleteOptions{
		PropagationPolicy: &policy,
		Preconditions:     &metav1.Preconditions{UID: &fresh.UID},
	}
	logger.Info("Cleaning up expired Job", "job", klog.KObj(fresh), "expiredAt", expiredAt.UTC())
	if err := tc.client.BatchV1().Jobs(fresh.Namespace).Delete(ctx, fresh.Name, options); err != nil {
		return jobOutcomeSkipped, err
	}
	return jobOutcomeDeleted, nil
}

// processTTL checks whether a Job's TTL has expired. If the TTL will expire in
// the future, the Job is re-enqueued after the remaining time.
func (tc *Controller) processTTL(ctx context.Context, logger klog.Logger, job *batch.Job) (expiredAt *time.Time, requeued bool, err error) {
	if job.DeletionTimestamp != nil || !needsCleanup(job) {
		return nil, false, nil
	}

	now := tc.clock.Now()
	t, e, err := timeLeft(logger, job, &now)
	if err != nil {
		return nil, false, err
	}

	if *t <= 0 {
		return e, false, nil
	}

	logger.V(2).Info("Job TTL has not expired yet; re-enqueueing", "job", klog.KObj(job), "remainingTTL", *t)
	if err := tc.enqueueAfter(ctx, cacheKey(job), *t); err != nil {
		return nil, false, err
	}
	return nil, true, nil
}

// needsCleanup checks whether a Job has finished and has a TTL set.
func needsCleanup(j *batch.Job) bool {
	return j.Spec.TTLSecondsAfterFinished != nil && jobutil.IsJobFinished(j)
}

func getFinishAndExpireTime(j *batch.Job) (*time.Time, *time.Time, error) {
	if !needsCleanup(j) {
		return nil, nil, fmt.Errorf("job %s/%s should not be cleaned up", j.Namespace, j.Name)
	}
	t, err := jobFinishTime(j)
	if err != nil {
		return nil, nil, err
	}
	finishAt := t.Time
	expireAt := finishAt.Add(time.Duration(*j.Spec.TTLSecondsAfterFinished) * time.Second)
	return &finishAt, &expireAt, nil
}

func timeLeft(logger klog.Logger, j *batch.Job, since *time.Time) (*time.Duration, *time.Time, error) {
	finishAt, expireAt, err := getFinishAndExpireTime(j)
	if err != nil {
		return nil, nil, err
	}

	if finishAt.After(*since) {
		logger.Info("Found Job finished in the future; cleanup will be deferred", "job", klog.KObj(j))
	}
	remaining := expireAt.Sub(*since)
	logger.V(4).Info("Found finished Job with TTL", "job", klog.KObj(j), "finishTime", finishAt.UTC(), "remainingTTL", remaining, "startTime", since.UTC(), "deadlineTTL", expireAt.UTC())
	return &remaining, expireAt, nil
}

// jobFinishTime takes an already finished Job and returns the time it finishes.
func jobFinishTime(finishedJob *batch.Job) (metav1.Time, error) {
	for _, c := range finishedJob.Status.Conditions {
		if (c.Type == batch.JobComplete || c.Type == batch.JobFailed) && c.Status == v1.ConditionTrue {
			finishAt := c.LastTransitionTime
			if finishAt.IsZero() {
				return metav1.Time{}, fmt.Errorf("unable to find the time when the Job %s/%s finished", finishedJob.Namespace, finishedJob.Name)
			}
			return c.LastTransitionTime, nil
		}
	}

	return metav1.Time{}, fmt.Errorf("unable to find the status of the finished Job %s/%s", finishedJob.Namespace, finishedJob.Name)
}

func cacheKey(job *batch.Job) string {
	return fmt.Sprintf("%s/%s", job.Namespace, job.Name)
}

func joinErrors(errs []error) error {
	var joined error
	for _, err := range errs {
		if err == nil {
			continue
		}
		if joined == nil {
			joined = err
			continue
		}
		joined = fmt.Errorf("%w; %w", joined, err)
	}
	return joined
}
