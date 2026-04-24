/*
Copyright 2024 The Kubernetes Authors.

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
	"errors"
	"lambda/pkg/scheduler/backend/awsstore"
	"sync"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/scheduler/framework"
	"k8s.io/kubernetes/pkg/scheduler/metrics"
)

// activeQueuer is a wrapper for activeQ related operations.
// Its methods, except "unlocked" ones, take the lock inside.
// Note: be careful when using unlocked() methods.
// getLock() methods should be used only for unlocked() methods
// and it is forbidden to call any other activeQueuer's method under this lock.
type activeQueuer interface {
	underLock(func(unlockedActiveQ unlockedActiveQueuer))
	underRLock(func(unlockedActiveQ unlockedActiveQueueReader))

	update(newPod *v1.Pod, oldPodInfo *framework.QueuedPodInfo) *framework.QueuedPodInfo
	delete(pInfo *framework.QueuedPodInfo) error
	pop(logger klog.Logger) (*framework.QueuedPodInfo, error)
	list() []*v1.Pod
	len() int
	has(pInfo *framework.QueuedPodInfo) bool

	schedulingCycle() int64
	done(pod types.UID)
	close()
	broadcast()
}

// unlockedActiveQueuer defines activeQ methods that are not protected by the lock itself.
// underLock() method should be used to protect these methods.
type unlockedActiveQueuer interface {
	unlockedActiveQueueReader
	add(pInfo *framework.QueuedPodInfo, event string) bool
}

// unlockedActiveQueueReader defines activeQ read-only methods that are not protected by the lock itself.
// underLock() or underRLock() method should be used to protect these methods.
type unlockedActiveQueueReader interface {
	get(pInfo *framework.QueuedPodInfo) (*framework.QueuedPodInfo, bool)
	has(pInfo *framework.QueuedPodInfo) bool
}

// unlockedActiveQueue defines activeQ methods that are not protected by the lock itself.
// activeQueue.underLock() or activeQueue.underRLock() method should be used to protect these methods.
type unlockedActiveQueue struct {
	queue *awsstore.ActiveQueueAWS
}

func newUnlockedActiveQueue(queue *awsstore.ActiveQueueAWS) *unlockedActiveQueue {
	return &unlockedActiveQueue{
		queue: queue,
	}
}

// add adds a new pod to the activeQ.
// The event should show which event triggered this addition and is used for the metric recording.
// This method should be called in activeQueue.underLock().
func (uaq *unlockedActiveQueue) add(pInfo *framework.QueuedPodInfo, event string) bool {
	if err := uaq.queue.Add(context.Background(), pInfo); err != nil {
		return false
	}
	metrics.SchedulerQueueIncomingPods.WithLabelValues("active", event).Inc()
	return true
}

// get returns the pod matching pInfo inside the activeQ.
// Returns false if the pInfo doesn't exist in the queue.
// This method should be called in activeQueue.underLock() or activeQueue.underRLock().
func (uaq *unlockedActiveQueue) get(pInfo *framework.QueuedPodInfo) (*framework.QueuedPodInfo, bool) {
	out, found, err := uaq.queue.Get(context.Background(), pInfo)
	if err != nil {
		return nil, false
	}
	return out, found
}

// has returns if pInfo exists in the queue.
// This method should be called in activeQueue.underLock() or activeQueue.underRLock().
func (uaq *unlockedActiveQueue) has(pInfo *framework.QueuedPodInfo) bool {
	found, err := uaq.queue.Has(context.Background(), pInfo)
	if err != nil {
		return false
	}
	return found
}

// activeQueue implements activeQueuer. All of the fields have to be protected using the lock.
type activeQueue struct {
	lock sync.RWMutex

	queue *awsstore.ActiveQueueAWS

	unlockedQueue *unlockedActiveQueue

	cond sync.Cond

	schedCycle int64

	closed bool
}

func newActiveQueue(store *awsstore.ActiveQueueAWS) *activeQueue {
	aq := &activeQueue{
		queue:         store,
		unlockedQueue: newUnlockedActiveQueue(store),
	}
	aq.cond.L = &aq.lock

	return aq
}

// underLock runs the fn function under the lock.Lock.
// fn can run unlockedActiveQueuer methods but should NOT run any other activeQueue method,
// as it would end up in deadlock.
func (aq *activeQueue) underLock(fn func(unlockedActiveQ unlockedActiveQueuer)) {
	aq.lock.Lock()
	defer aq.lock.Unlock()
	fn(aq.unlockedQueue)
}

// underLock runs the fn function under the lock.RLock.
// fn can run unlockedActiveQueueReader methods but should NOT run any other activeQueue method,
// as it would end up in deadlock.
func (aq *activeQueue) underRLock(fn func(unlockedActiveQ unlockedActiveQueueReader)) {
	aq.lock.RLock()
	defer aq.lock.RUnlock()
	fn(aq.unlockedQueue)
}

// update updates the pod in activeQ if oldPodInfo is already in the queue.
// It returns new pod info if updated, nil otherwise.
func (aq *activeQueue) update(newPod *v1.Pod, oldPodInfo *framework.QueuedPodInfo) *framework.QueuedPodInfo {
	aq.lock.Lock()
	defer aq.lock.Unlock()

	pInfo, err := aq.queue.Update(context.Background(), newPod, oldPodInfo)
	if err != nil {
		return nil
	}
	return pInfo
}

// delete deletes the pod info from activeQ.
func (aq *activeQueue) delete(pInfo *framework.QueuedPodInfo) error {
	aq.lock.Lock()
	defer aq.lock.Unlock()

	return aq.queue.Delete(context.Background(), pInfo)
}

// pop removes the head of the queue and returns it.
// It blocks if the queue is empty and waits until a new item is added to the queue.
// It increments scheduling cycle when a pod is popped.
func (aq *activeQueue) pop(logger klog.Logger) (*framework.QueuedPodInfo, error) {
	aq.lock.Lock()
	defer aq.lock.Unlock()

	return aq.unlockedPop(logger)
}

func (aq *activeQueue) unlockedPop(logger klog.Logger) (*framework.QueuedPodInfo, error) {
	if aq.closed {
		logger.V(2).Info("Scheduling queue is closed")
		return nil, nil
	}

	// non-blocking pop
	pInfo, err := aq.queue.Pop(context.Background())
	if err != nil {
		if errors.Is(err, awsstore.ErrQueueEmpty) {
			return nil, awsstore.ErrQueueEmpty
		}
		return nil, err
	}

	aq.schedCycle++
	return pInfo, nil
}

// list returns all pods that are in the queue.
func (aq *activeQueue) list() []*v1.Pod {
	aq.lock.RLock()
	defer aq.lock.RUnlock()

	pInfos, err := aq.queue.List(context.Background())
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
func (aq *activeQueue) len() int {
	aq.lock.RLock()
	defer aq.lock.RUnlock()

	n, err := aq.queue.Len(context.Background())
	if err != nil {
		return 0
	}
	return n
}

// has inform if pInfo exists in the queue.
func (aq *activeQueue) has(pInfo *framework.QueuedPodInfo) bool {
	aq.lock.RLock()
	defer aq.lock.RUnlock()

	found, err := aq.queue.Has(context.Background(), pInfo)
	if err != nil {
		return false
	}
	return found
}

func (aq *activeQueue) schedulingCycle() int64 {
	aq.lock.RLock()
	defer aq.lock.RUnlock()
	return aq.schedCycle
}

// done must be called for pod returned by Pop. This allows the queue to
// keep track of which pods are currently being processed.
func (aq *activeQueue) done(pod types.UID) {
	aq.lock.Lock()
	defer aq.lock.Unlock()

	aq.unlockedDone(pod)
}

// unlockedDone is used by the activeQueue internally and doesn't take the lock itself.
// It assumes the lock is already taken outside before the method is called.
func (aq *activeQueue) unlockedDone(pod types.UID) {
	return
}

// close closes the activeQueue.
func (aq *activeQueue) close() {
	aq.lock.Lock()
	defer aq.lock.Unlock()
	aq.closed = true
}

// broadcast notifies the pop() operation that new pod(s) was added to the activeQueue.
func (aq *activeQueue) broadcast() {
	aq.cond.Broadcast()
}
