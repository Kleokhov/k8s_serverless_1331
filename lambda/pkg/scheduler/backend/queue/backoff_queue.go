/*
Copyright 2025 The Kubernetes Authors.

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

package queue

import (
	"context"
	"lambda/pkg/scheduler/backend/awsstore"
	"sync"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/scheduler/framework"
	"k8s.io/kubernetes/pkg/scheduler/metrics"
	"k8s.io/utils/clock"
)

// backoffQOrderingWindowDuration is a duration of an ordering window in the podBackoffQ.
// In each window, represented as a whole second, pods are ordered by priority.
// It is the same as interval of flushing the pods from the podBackoffQ to the activeQ, to flush the whole windows there.
// This works only if PopFromBackoffQ feature is enabled.
// See the KEP-5142 (http://kep.k8s.io/5142) for rationale.
const backoffQOrderingWindowDuration = time.Second

// backoffQueuer is a wrapper for backoffQ related operations.
// Its methods that relies on the queues, take the lock inside.
type backoffQueuer interface {
	isPodBackingoff(podInfo *framework.QueuedPodInfo) bool
	popAllBackoffCompleted(logger klog.Logger) []*framework.QueuedPodInfo
	// podInitialBackoffDuration returns initial backoff duration that pod can get.
	podInitialBackoffDuration() time.Duration
	// podMaxBackoffDuration returns maximum backoff duration that pod can get.
	podMaxBackoffDuration() time.Duration
	// waitUntilAlignedWithOrderingWindow waits until the time reaches a multiple of backoffQOrderingWindowDuration.
	// It then runs the f function at the backoffQOrderingWindowDuration interval using a ticker.
	// It's important to align the flushing time, because podBackoffQ's ordering is based on the windows
	// and whole windows have to be flushed at one time without a visible latency.
	waitUntilAlignedWithOrderingWindow(f func(), stopCh <-chan struct{})

	// add adds the pInfo to backoffQueue.
	// The event should show which event triggered this addition and is used for the metric recording.
	// It also ensures that pInfo is not in both queues.
	add(logger klog.Logger, pInfo *framework.QueuedPodInfo, event string) bool
	// update updates the pod in backoffQueue if oldPodInfo is already in the queue.
	// It returns new pod info if updated, nil otherwise.
	update(newPod *v1.Pod, oldPodInfo *framework.QueuedPodInfo) *framework.QueuedPodInfo
	// delete deletes the pInfo from backoffQueue.
	// It returns true if the pod was deleted.
	delete(pInfo *framework.QueuedPodInfo) bool
	// get returns the pInfo matching given pInfoLookup, if exists.
	get(pInfoLookup *framework.QueuedPodInfo) (*framework.QueuedPodInfo, bool)
	// has inform if pInfo exists in the queue.
	has(pInfo *framework.QueuedPodInfo) bool
	// list returns all pods that are in the queue.
	list() []*v1.Pod
	// len returns length of the queue.
	len() int
}

// backoffQueue implements backoffQueuer and wraps two queues inside,
// providing seamless access as if it were one queue.
type backoffQueue struct {
	lock              sync.RWMutex
	clock             clock.WithTicker
	store             *awsstore.BackoffQueuesAWS
	podInitialBackoff time.Duration
	podMaxBackoff     time.Duration
}

func newBackoffQueue(
	clock clock.WithTicker,
	podInitialBackoffDuration time.Duration,
	podMaxBackoffDuration time.Duration,
	store *awsstore.BackoffQueuesAWS) *backoffQueue {
	bq := &backoffQueue{
		clock:             clock,
		store:             store,
		podInitialBackoff: podInitialBackoffDuration,
		podMaxBackoff:     podMaxBackoffDuration,
	}
	return bq
}

// podInitialBackoffDuration returns initial backoff duration that pod can get.
func (bq *backoffQueue) podInitialBackoffDuration() time.Duration {
	return bq.podInitialBackoff
}

// podMaxBackoffDuration returns maximum backoff duration that pod can get.
func (bq *backoffQueue) podMaxBackoffDuration() time.Duration {
	return bq.podMaxBackoff
}

// alignToWindow truncates the provided time to the podBackoffQ ordering window.
// It returns the lowest possible timestamp in the window.
func (bq *backoffQueue) alignToWindow(t time.Time) time.Time {
	return t
}

// waitUntilAlignedWithOrderingWindow waits until the time reaches a multiple of backoffQOrderingWindowDuration.
// It then runs the f function at the backoffQOrderingWindowDuration interval using a ticker.
// It's important to align the flushing time, because podBackoffQ's ordering is based on the windows
// and whole windows have to be flushed at one time without a visible latency.
func (bq *backoffQueue) waitUntilAlignedWithOrderingWindow(f func(), stopCh <-chan struct{}) {
	now := bq.clock.Now()
	// Wait until the time reaches the multiple of backoffQOrderingWindowDuration.
	durationToNextWindow := bq.alignToWindow(now.Add(backoffQOrderingWindowDuration)).Sub(now)
	timer := bq.clock.NewTimer(durationToNextWindow)
	select {
	case <-stopCh:
		timer.Stop()
		return
	case <-timer.C():
	}

	// Run a ticker to make sure the invocations of f function
	// are aligned with the backoffQ's ordering window.
	ticker := bq.clock.NewTicker(backoffQOrderingWindowDuration)
	for {
		select {
		case <-stopCh:
			return
		default:
		}

		f()

		// NOTE: b/c there is no priority selection in golang
		// it is possible for this to race, meaning we could
		// trigger ticker.C and stopCh, and ticker.C select falls through.
		// In order to mitigate we re-check stopCh at the beginning
		// of every loop to prevent extra executions of f().
		select {
		case <-stopCh:
			ticker.Stop()
			return
		case <-ticker.C():
		}
	}
}

// isPodBackingoff returns true if a pod is still waiting for its backoff timer.
// If this returns true, the pod should not be re-tried.
// If the pod backoff time is in the actual ordering window, it should still be backing off.
func (bq *backoffQueue) isPodBackingoff(podInfo *framework.QueuedPodInfo) bool {
	boTime := bq.getBackoffTime(podInfo)
	// Don't use After, because in case of windows equality we want to return true.
	return !boTime.Before(bq.alignToWindow(bq.clock.Now()))
}

// getBackoffTime returns the time that podInfo completes backoff.
// It caches the result in podInfo.BackoffExpiration and returns this value in subsequent calls.
// The cache will be cleared when this pod is poped from the scheduling queue again (i.e., at activeQ's pop),
// because of the fact that the backoff time is calculated based on podInfo.Attempts,
// which doesn't get changed until the pod's scheduling is retried.
func (bq *backoffQueue) getBackoffTime(podInfo *framework.QueuedPodInfo) time.Time {
	if podInfo.Attempts == 0 {
		// Don't store backoff expiration if the duration is 0
		// to correctly handle isPodBackingoff, if pod should skip backoff, when it wasn't tried at all.
		return time.Time{}
	}
	if podInfo.BackoffExpiration.IsZero() {
		duration := bq.calculateBackoffDuration(podInfo)
		podInfo.BackoffExpiration = bq.alignToWindow(podInfo.Timestamp.Add(duration))
	}
	return podInfo.BackoffExpiration
}

// calculateBackoffDuration is a helper function for calculating the backoffDuration
// based on the number of attempts the pod has made.
func (bq *backoffQueue) calculateBackoffDuration(podInfo *framework.QueuedPodInfo) time.Duration {
	if podInfo.Attempts == 0 {
		// When the Pod hasn't experienced any scheduling attempts,
		// they aren't obliged to get a backoff penalty at all.
		return 0
	}

	duration := bq.podInitialBackoff
	for i := 1; i < podInfo.Attempts; i++ {
		// Use subtraction instead of addition or multiplication to avoid overflow.
		if duration > bq.podMaxBackoff-duration {
			return bq.podMaxBackoff
		}
		duration += duration
	}
	return duration
}

// popAllBackoffCompleted pops all pods from podBackoffQ and podErrorBackoffQ that completed backoff.
func (bq *backoffQueue) popAllBackoffCompleted(logger klog.Logger) []*framework.QueuedPodInfo {
	bq.lock.Lock()
	defer bq.lock.Unlock()

	pods, err := bq.store.PopAllBackoffCompleted(context.Background())
	if err != nil {
		logger.Error(err, "Unable to pop pods from backoff queues")
		return nil
	}
	return pods
}

// add adds the pInfo to backoffQueue.
// The event should show which event triggered this addition and is used for the metric recording.
// It also ensures that pInfo is not in both queues.
func (bq *backoffQueue) add(logger klog.Logger, pInfo *framework.QueuedPodInfo, event string) bool {
	bq.lock.Lock()
	defer bq.lock.Unlock()

	if err := bq.store.Add(context.Background(), pInfo); err != nil {
		logger.Error(err, "Unable to add pod to backoff queue", "pod", klog.KObj(pInfo.Pod))
		return false
	}
	metrics.SchedulerQueueIncomingPods.WithLabelValues("backoff", event).Inc()
	return true
}

// update updates the pod in backoffQueue if oldPodInfo is already in the queue.
// It returns new pod info if updated, nil otherwise.
func (bq *backoffQueue) update(newPod *v1.Pod, oldPodInfo *framework.QueuedPodInfo) *framework.QueuedPodInfo {
	bq.lock.Lock()
	defer bq.lock.Unlock()

	pInfo, err := bq.store.Update(context.Background(), newPod, oldPodInfo)
	if err != nil {
		return nil
	}
	return pInfo
}

// delete deletes the pInfo from backoffQueue.
// It returns true if the pod was deleted.
func (bq *backoffQueue) delete(pInfo *framework.QueuedPodInfo) bool {
	bq.lock.Lock()
	defer bq.lock.Unlock()

	deleted, err := bq.store.Delete(context.Background(), pInfo)
	if err != nil {
		return false
	}
	return deleted
}

// popBackoff pops the pInfo from the podBackoffQ.
// It returns error if the queue is empty.
// This doesn't pop the pods from the podErrorBackoffQ.
func (bq *backoffQueue) popBackoff() (*framework.QueuedPodInfo, error) {
	bq.lock.Lock()
	defer bq.lock.Unlock()

	return bq.store.Pop(context.Background())
}

// get returns the pInfo matching given pInfoLookup, if exists.
func (bq *backoffQueue) get(pInfoLookup *framework.QueuedPodInfo) (*framework.QueuedPodInfo, bool) {
	bq.lock.RLock()
	defer bq.lock.RUnlock()

	pInfo, found, err := bq.store.Get(context.Background(), pInfoLookup)
	if err != nil {
		return nil, false
	}
	return pInfo, found
}

// has inform if pInfo exists in the queue.
func (bq *backoffQueue) has(pInfo *framework.QueuedPodInfo) bool {
	bq.lock.RLock()
	defer bq.lock.RUnlock()

	found, err := bq.store.Has(context.Background(), pInfo)
	if err != nil {
		return false
	}
	return found
}

// list returns all pods that are in the queue.
func (bq *backoffQueue) list() []*v1.Pod {
	bq.lock.RLock()
	defer bq.lock.RUnlock()

	pInfos, err := bq.store.List(context.Background())
	if err != nil {
		return nil
	}

	result := make([]*v1.Pod, 0, len(pInfos))
	for _, pInfo := range pInfos {
		result = append(result, pInfo.Pod)
	}
	return result
}

// len returns length of the queue.
func (bq *backoffQueue) len() int {
	bq.lock.RLock()
	defer bq.lock.RUnlock()

	n, err := bq.store.Len(context.Background())
	if err != nil {
		return 0
	}
	return n
}

// lenBackoff returns length of the podBackoffQ.
func (bq *backoffQueue) lenBackoff() int {
	bq.lock.RLock()
	defer bq.lock.RUnlock()

	n, err := bq.store.LenBackoff(context.Background())
	if err != nil {
		return 0
	}
	return n
}
