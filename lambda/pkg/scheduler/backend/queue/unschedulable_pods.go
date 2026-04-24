package queue

import (
	"context"
	"lambda/pkg/scheduler/backend/awsstore"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/kubernetes/pkg/scheduler/framework"
	"k8s.io/kubernetes/pkg/scheduler/metrics"
	"k8s.io/kubernetes/pkg/scheduler/util"
)

const unschedulablePartitionKey = "UNSCHEDULABLE"

// UnschedulablePods holds pods that cannot be scheduled. This data structure
// is used to implement unschedulablePods.
type UnschedulablePods struct {
	store                                awsstore.DynamoMap
	keyFunc                              func(*v1.Pod) string
	unschedulableRecorder, gatedRecorder metrics.MetricRecorder
}

type unschedulableEntry struct {
	Key     string
	PInfo   *framework.QueuedPodInfo
	Version int64
}

// newUnschedulablePods initializes a new object of UnschedulablePods.
func newUnschedulablePods(store awsstore.DynamoMap, unschedulableRecorder, gatedRecorder metrics.MetricRecorder) *UnschedulablePods {
	return &UnschedulablePods{
		store:                 store,
		keyFunc:               util.GetPodFullName,
		unschedulableRecorder: unschedulableRecorder,
		gatedRecorder:         gatedRecorder,
	}
}

// addOrUpdate adds a pod to the unschedulable podInfoMap.
// The event should show which event triggered the addition and is used for the metric recording.
func (u *UnschedulablePods) addOrUpdate(pInfo *framework.QueuedPodInfo, event string) {
	if pInfo == nil || pInfo.Pod == nil {
		return
	}

	ctx := context.Background()
	sk := u.keyFunc(pInfo.Pod)

	_, exists, err := u.store.Get(ctx, unschedulablePartitionKey, sk)
	if err != nil {
		return
	}

	payload, err := awsstore.MarshalQueuedPodInfo(pInfo)
	if err != nil {
		return
	}

	if err := u.store.Upsert(ctx, unschedulablePartitionKey, sk, payload, nil); err != nil {
		return
	}

	if !exists {
		if pInfo.Gated {
			if u.gatedRecorder != nil {
				u.gatedRecorder.Inc()
			}
		} else {
			if u.unschedulableRecorder != nil {
				u.unschedulableRecorder.Inc()
			}
		}
		metrics.SchedulerQueueIncomingPods.WithLabelValues("unschedulable", event).Inc()
	}
}

// delete deletes a pod from the unschedulable podInfoMap.
// The `gated` parameter is used to figure out which metric should be decreased.
func (u *UnschedulablePods) delete(pod *v1.Pod, gated bool) {
	if pod == nil {
		return
	}

	ctx := context.Background()
	sk := u.keyFunc(pod)

	deleted, err := u.store.Delete(ctx, unschedulablePartitionKey, sk)
	if err != nil || !deleted {
		return
	}

	if gated {
		if u.gatedRecorder != nil {
			u.gatedRecorder.Dec()
		}
	} else {
		if u.unschedulableRecorder != nil {
			u.unschedulableRecorder.Dec()
		}
	}
}

func (u *UnschedulablePods) deleteIfVersion(
	ctx context.Context,
	pod *v1.Pod,
	expectedVersion int64,
	gated bool,
) (bool, error) {
	if pod == nil {
		return false, nil
	}

	sk := u.keyFunc(pod)
	deleted, err := u.store.DeleteIfVersion(ctx, unschedulablePartitionKey, sk, expectedVersion)
	if err != nil || !deleted {
		return deleted, err
	}

	if gated {
		if u.gatedRecorder != nil {
			u.gatedRecorder.Dec()
		}
	} else {
		if u.unschedulableRecorder != nil {
			u.unschedulableRecorder.Dec()
		}
	}
	return true, nil
}

// get returns the QueuedPodInfo if a pod with the same key as the key of the given "pod"
// is found in the map. It returns nil otherwise.
func (u *UnschedulablePods) get(pod *v1.Pod) *framework.QueuedPodInfo {
	if pod == nil {
		return nil
	}

	item, found, err := u.store.Get(context.Background(), unschedulablePartitionKey, u.keyFunc(pod))
	if err != nil || !found {
		return nil
	}

	pInfo, err := awsstore.UnmarshalQueuedPodInfo(item.Payload)
	if err != nil {
		return nil
	}
	return pInfo
}

func (u *UnschedulablePods) list() []*framework.QueuedPodInfo {
	items, err := u.store.ListPartition(context.Background(), unschedulablePartitionKey)
	if err != nil {
		return nil
	}

	out := make([]*framework.QueuedPodInfo, 0, len(items))
	for _, item := range items {
		pInfo, err := awsstore.UnmarshalQueuedPodInfo(item.Payload)
		if err != nil {
			continue
		}
		out = append(out, pInfo)
	}
	return out
}

func (u *UnschedulablePods) listOlderThan(
	ctx context.Context,
	cutoff time.Time,
) ([]*unschedulableEntry, error) {
	items, err := u.store.ListPartition(ctx, unschedulablePartitionKey)
	if err != nil {
		return nil, err
	}

	out := make([]*unschedulableEntry, 0, len(items))
	for _, item := range items {
		pInfo, err := awsstore.UnmarshalQueuedPodInfo(item.Payload)
		if err != nil {
			continue
		}
		if pInfo.Timestamp.Before(cutoff) {
			out = append(out, &unschedulableEntry{
				Key:     item.SK,
				PInfo:   pInfo,
				Version: item.Version,
			})
		}
	}
	return out, nil
}

func (u *UnschedulablePods) len() int {
	n, err := u.store.CountPartition(context.Background(), unschedulablePartitionKey)
	if err != nil {
		return 0
	}
	return n
}

// clear removes all the entries from the unschedulable podInfoMap.
func (u *UnschedulablePods) clear() {
	items, err := u.store.ListPartition(context.Background(), unschedulablePartitionKey)
	if err == nil {
		for _, item := range items {
			_, _ = u.store.Delete(context.Background(), item.PK, item.SK)
		}
	}

	if u.unschedulableRecorder != nil {
		u.unschedulableRecorder.Clear()
	}
	if u.gatedRecorder != nil {
		u.gatedRecorder.Clear()
	}
}
