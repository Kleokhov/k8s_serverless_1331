package awsstore

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/kubernetes/pkg/scheduler/framework"
)

const (
	cachePodStatePK = "CACHE#PODSTATE"
	cacheAssumedPK  = "CACHE#ASSUMED"
	cacheNodePK     = "CACHE#NODE"
)

type CacheStore struct {
	store DynamoMap
}

func NewCacheStore(store DynamoMap) *CacheStore {
	return &CacheStore{store: store}
}

// ---------------------------  POD STATE  --------------------------- //

func (s *CacheStore) GetPodState(ctx context.Context, podKey string) (*PodStateRecord, bool, int64, error) {
	item, found, err := s.store.Get(ctx, cachePodStatePK, podKey)
	if err != nil || !found {
		return nil, found, 0, err
	}
	rec, err := unmarshalPodStateRecord(item.Payload)
	if err != nil {
		return nil, false, 0, err
	}
	return rec, true, item.Version, nil
}

func (s *CacheStore) UpsertPodState(ctx context.Context, podKey string, rec *PodStateRecord) error {
	payload, err := marshalJSON(rec)
	if err != nil {
		return err
	}
	return s.store.Upsert(ctx, cachePodStatePK, podKey, payload, nil)
}

func (s *CacheStore) DeletePodState(ctx context.Context, podKey string) (bool, error) {
	return s.store.Delete(ctx, cachePodStatePK, podKey)
}

// ---------------------------  ASSUMED POD  --------------------------- //

func (s *CacheStore) AddAssumedPod(ctx context.Context, podKey string) error {
	payload, err := marshalJSON(&AssumedPodRecord{PodKey: podKey})
	if err != nil {
		return err
	}
	return s.store.Upsert(ctx, cacheAssumedPK, podKey, payload, nil)
}

func (s *CacheStore) DeleteAssumedPod(ctx context.Context, podKey string) (bool, error) {
	return s.store.Delete(ctx, cacheAssumedPK, podKey)
}

func (s *CacheStore) IsAssumedPod(ctx context.Context, podKey string) (bool, error) {
	_, found, err := s.store.Get(ctx, cacheAssumedPK, podKey)
	return found, err
}

func (s *CacheStore) ListAssumedPodKeys(ctx context.Context) ([]string, error) {
	items, err := s.store.ListPartition(ctx, cacheAssumedPK)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.SK)
	}
	return out, nil
}

func (s *CacheStore) ListPodStates(ctx context.Context) (map[string]*PodStateRecord, error) {
	items, err := s.store.ListPartition(ctx, cachePodStatePK)
	if err != nil {
		return nil, err
	}
	out := make(map[string]*PodStateRecord, len(items))
	for _, item := range items {
		rec, err := unmarshalPodStateRecord(item.Payload)
		if err != nil {
			continue
		}
		out[item.SK] = rec
	}
	return out, nil
}

// ---------------------------  NODE  --------------------------- //

func (s *CacheStore) GetNode(ctx context.Context, nodeName string) (*NodeRecord, bool, int64, error) {
	item, found, err := s.store.Get(ctx, cacheNodePK, nodeName)
	if err != nil || !found {
		return nil, found, 0, err
	}
	rec, err := unmarshalNodeRecord(item.Payload)
	if err != nil {
		return nil, false, 0, err
	}
	return rec, true, item.Version, nil
}

func (s *CacheStore) UpsertNode(ctx context.Context, nodeName string, rec *NodeRecord) error {
	payload, err := marshalJSON(rec)
	if err != nil {
		return err
	}
	return s.store.Upsert(ctx, cacheNodePK, nodeName, payload, nil)
}

func (s *CacheStore) DeleteNode(ctx context.Context, nodeName string) (bool, error) {
	return s.store.Delete(ctx, cacheNodePK, nodeName)
}

func (s *CacheStore) ListNodes(ctx context.Context) (map[string]*NodeRecord, error) {
	items, err := s.store.ListPartition(ctx, cacheNodePK)
	if err != nil {
		return nil, err
	}
	out := make(map[string]*NodeRecord, len(items))
	for _, item := range items {
		rec, err := unmarshalNodeRecord(item.Payload)
		if err != nil {
			continue
		}
		out[item.SK] = rec
	}
	return out, nil
}

// ---------------------------  POD  --------------------------- //

func NewNodeRecord() *NodeRecord {
	return &NodeRecord{
		Pods:      []*corev1.Pod{},
		UpdatedAt: time.Now(),
	}
}

func (r *NodeRecord) AddPod(pod *corev1.Pod) error {
	for _, existing := range r.Pods {
		key1, _ := framework.GetPodKey(existing)
		key2, _ := framework.GetPodKey(pod)
		if key1 == key2 {
			return fmt.Errorf("pod already exists on node")
		}
	}
	r.Pods = append(r.Pods, pod)
	r.Generation++
	r.UpdatedAt = time.Now()
	return nil
}

func (r *NodeRecord) ReplacePod(oldPod, newPod *corev1.Pod) error {
	if oldPod == nil || newPod == nil {
		return fmt.Errorf("oldPod and newPod are required")
	}

	oldKey, err := framework.GetPodKey(oldPod)
	if err != nil {
		return err
	}
	newKey, err := framework.GetPodKey(newPod)
	if err != nil {
		return err
	}
	if oldKey != newKey {
		return fmt.Errorf("pod key mismatch during replace")
	}

	for i, existing := range r.Pods {
		key, _ := framework.GetPodKey(existing)
		if key == oldKey {
			r.Pods[i] = newPod
			r.Generation++
			r.UpdatedAt = time.Now()
			return nil
		}
	}

	return fmt.Errorf("pod not found on node")
}

func (r *NodeRecord) RemovePod(pod *corev1.Pod) error {
	key, err := framework.GetPodKey(pod)
	if err != nil {
		return err
	}
	next := make([]*corev1.Pod, 0, len(r.Pods))
	found := false
	for _, p := range r.Pods {
		k, _ := framework.GetPodKey(p)
		if k == key {
			found = true
			continue
		}
		next = append(next, p)
	}
	if !found {
		return fmt.Errorf("pod not found on node")
	}
	r.Pods = next
	r.Generation++
	r.UpdatedAt = time.Now()
	return nil
}
