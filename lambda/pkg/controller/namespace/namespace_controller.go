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

package namespace

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"lambda/pkg/controller/awsstore"

	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"
	"k8s.io/kubernetes/pkg/controller/namespace/deletion"

	"k8s.io/klog/v2"
	"k8s.io/utils/clock"
)

const (
	// namespaceDeletionGracePeriod is the time period to wait before processing a received namespace event.
	// This allows time for the following to occur:
	// * lifecycle admission plugins on HA apiservers to also observe a namespace
	//   deletion and prevent new objects from being created in the terminating namespace
	// * non-leader etcd servers to observe last-minute object creations in a namespace
	//   so this controller's cleanup can actually clean up all objects
	namespaceDeletionGracePeriod = 5 * time.Second

	DefaultQueueBatchSize         int32         = 10
	DefaultQueueVisibilityTimeout time.Duration = 30 * time.Second
)

// NamespaceController is responsible for cleaning up terminating namespaces.
// In the serverless flow, namespace names arrive through SQS and RunOnce
// processes a single batch without resident workers or event handlers.
type NamespaceController struct {
	queue workqueue
	// client for direct namespace lookups
	client clientset.Interface
	// helper to delete all resources in the namespace when the namespace is deleted.
	namespacedResourcesDeleter deletion.NamespacedResourcesDeleterInterface

	queueBatchSize         int32
	queueVisibilityTimeout time.Duration

	clock clock.Clock
}

type workqueue interface {
	EnqueueAfter(ctx context.Context, body string, delay time.Duration) error
	Dequeue(ctx context.Context, maxMessages int32, visibilityTimeout time.Duration) ([]awsstore.QueuedItem, error)
	Delete(ctx context.Context, receiptHandle string) error
}

type Option func(*NamespaceController)

func WithQueueBatchSize(size int32) Option {
	return func(nm *NamespaceController) {
		if size > 0 {
			nm.queueBatchSize = size
		}
	}
}

func WithQueueVisibilityTimeout(d time.Duration) Option {
	return func(nm *NamespaceController) {
		if d >= 0 {
			nm.queueVisibilityTimeout = d
		}
	}
}

type Result struct {
	NamespacesDequeued  int `json:"namespacesDequeued"`
	NamespacesProcessed int `json:"namespacesProcessed"`
	NamespacesRequeued  int `json:"namespacesRequeued"`
	NamespacesSkipped   int `json:"namespacesSkipped"`
	NamespacesFailed    int `json:"namespacesFailed"`
}

type processOutcome int

const (
	namespaceOutcomeSkipped processOutcome = iota
	namespaceOutcomeRequeued
	namespaceOutcomeProcessed
)

// NewLambdaController creates a serverless namespace controller.
func NewLambdaController(
	ctx context.Context,
	queue awsstore.SQSQueue,
	kubeClient clientset.Interface,
	metadataClient metadata.Interface,
	opts ...Option,
) (*NamespaceController, error) {
	if kubeClient == nil {
		return nil, fmt.Errorf("nil kube client")
	}
	if metadataClient == nil {
		return nil, fmt.Errorf("nil metadata client")
	}
	if queue == nil {
		return nil, fmt.Errorf("nil namespace queue")
	}

	nm := &NamespaceController{
		queue:  queue,
		client: kubeClient,
		namespacedResourcesDeleter: deletion.NewNamespacedResourcesDeleter(
			ctx,
			kubeClient.CoreV1().Namespaces(),
			metadataClient,
			kubeClient.CoreV1(),
			kubeClient.Discovery().ServerPreferredNamespacedResources,
			v1.FinalizerKubernetes,
		),
		queueBatchSize:         DefaultQueueBatchSize,
		queueVisibilityTimeout: DefaultQueueVisibilityTimeout,
		clock:                  clock.RealClock{},
	}

	for _, opt := range opts {
		opt(nm)
	}

	return nm, nil
}

func (nm *NamespaceController) enqueueNamespaceAfter(ctx context.Context, namespace string, delay time.Duration) error {
	namespace = strings.TrimSpace(namespace)
	if namespace == "" {
		return fmt.Errorf("empty namespace key")
	}
	if delay < 0 {
		delay = 0
	}
	return nm.queue.EnqueueAfter(ctx, namespace, delay)
}

// RunOnce dequeues a batch of namespaces from SQS and processes each one once.
func (nm *NamespaceController) RunOnce(ctx context.Context) (Result, error) {
	logger := klog.FromContext(ctx)

	items, err := nm.queue.Dequeue(ctx, nm.queueBatchSize, nm.queueVisibilityTimeout)
	if err != nil {
		return Result{}, fmt.Errorf("dequeue namespaces: %w", err)
	}

	result := Result{NamespacesDequeued: len(items)}
	var errs []error

	for _, item := range items {
		key := strings.TrimSpace(item.Body)
		if key == "" {
			logger.V(2).Info("Skipping empty namespace queue message")
			if delErr := nm.queue.Delete(ctx, item.ReceiptHandle); delErr != nil {
				errs = append(errs, fmt.Errorf("delete empty namespace queue item: %w", delErr))
			}
			result.NamespacesDequeued--
			continue
		}

		outcome, processErr := nm.processNamespace(ctx, key)
		if processErr != nil {
			logger.Error(processErr, "Failed to process namespace", "namespace", key)
			errs = append(errs, fmt.Errorf("process namespace %q: %w", key, processErr))
			result.NamespacesFailed++
			continue
		}

		switch outcome {
		case namespaceOutcomeProcessed:
			result.NamespacesProcessed++
		case namespaceOutcomeRequeued:
			result.NamespacesRequeued++
		default:
			result.NamespacesSkipped++
		}

		if delErr := nm.queue.Delete(ctx, item.ReceiptHandle); delErr != nil {
			errs = append(errs, fmt.Errorf("delete namespace queue item for %q: %w", key, delErr))
		}
	}

	logger.Info("Namespace controller invocation completed",
		"namespacesDequeued", result.NamespacesDequeued,
		"namespacesProcessed", result.NamespacesProcessed,
		"namespacesRequeued", result.NamespacesRequeued,
		"namespacesSkipped", result.NamespacesSkipped,
		"namespacesFailed", result.NamespacesFailed,
	)

	return result, errors.Join(errs...)
}

// ProcessItems processes pre-delivered queue items (from an SQS event trigger) and
// returns the message IDs of items that failed and should be retried.
func (nm *NamespaceController) ProcessItems(ctx context.Context, items []awsstore.QueuedItem) (Result, []string) {
	logger := klog.FromContext(ctx)
	result := Result{NamespacesDequeued: len(items)}
	var failedIDs []string

	for _, item := range items {
		key := strings.TrimSpace(item.Body)
		if key == "" {
			logger.V(2).Info("Skipping empty namespace queue message")
			result.NamespacesDequeued--
			continue
		}
		outcome, processErr := nm.processNamespace(ctx, key)
		if processErr != nil {
			logger.Error(processErr, "Failed to process namespace", "namespace", key)
			result.NamespacesFailed++
			failedIDs = append(failedIDs, item.MessageID)
			continue
		}
		switch outcome {
		case namespaceOutcomeProcessed:
			result.NamespacesProcessed++
		case namespaceOutcomeRequeued:
			result.NamespacesRequeued++
		default:
			result.NamespacesSkipped++
		}
	}
	return result, failedIDs
}

func (nm *NamespaceController) processNamespace(ctx context.Context, key string) (processOutcome, error) {
	startTime := nm.clock.Now()
	logger := klog.FromContext(ctx)
	defer func() {
		logger.V(4).Info("Finished syncing namespace", "namespace", key, "duration", nm.clock.Since(startTime))
	}()

	namespace, err := nm.client.CoreV1().Namespaces().Get(ctx, key, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		logger.Info("Namespace has been deleted", "namespace", key)
		return namespaceOutcomeSkipped, nil
	}
	if err != nil {
		return namespaceOutcomeSkipped, err
	}
	if namespace.DeletionTimestamp == nil || namespace.DeletionTimestamp.IsZero() {
		return namespaceOutcomeSkipped, nil
	}

	if remainingGrace := namespace.DeletionTimestamp.Time.Add(namespaceDeletionGracePeriod).Sub(nm.clock.Now()); remainingGrace > 0 {
		logger.V(2).Info("Namespace still within deletion grace period; re-enqueueing", "namespace", key, "remaining", remainingGrace)
		if err := nm.enqueueNamespaceAfter(ctx, key, remainingGrace); err != nil {
			return namespaceOutcomeSkipped, err
		}
		return namespaceOutcomeRequeued, nil
	}

	err = nm.namespacedResourcesDeleter.Delete(ctx, namespace.Name)
	if err == nil {
		logger.Info("Namespace cleanup processed", "namespace", namespace.Name)
		return namespaceOutcomeProcessed, nil
	}

	if estimate, ok := err.(*deletion.ResourcesRemainingError); ok {
		delaySeconds := estimate.Estimate/2 + 1
		delay := time.Duration(delaySeconds) * time.Second
		logger.V(2).Info("Content remaining in namespace; re-enqueueing", "namespace", key, "delay", delay)
		if enqueueErr := nm.enqueueNamespaceAfter(ctx, key, delay); enqueueErr != nil {
			return namespaceOutcomeSkipped, enqueueErr
		}
		return namespaceOutcomeRequeued, nil
	}

	return namespaceOutcomeSkipped, err
}
