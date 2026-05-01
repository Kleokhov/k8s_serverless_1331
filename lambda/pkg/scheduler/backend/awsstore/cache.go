package awsstore

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/kubernetes/pkg/scheduler/framework"
)

const (
	cachePodStatePK    = "CACHE#PODSTATE"
	cacheAssumedPK     = "CACHE#ASSUMED"
	cacheNodePK        = "CACHE#NODE"
	cacheNodePodPrefix = "CACHE#NODEPOD#"
)

// cacheNodePodPK returns the partition key under which the per-pod records for
// the given node are stored. Each pod is its own DynamoDB item, keyed by pod
// UID, so a node with N pods occupies N small items rather than one item that
// would otherwise blow past the 400 KB DynamoDB limit.
func cacheNodePodPK(nodeName string) string {
	return cacheNodePodPrefix + nodeName
}

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

// ---------------------------  NODE METADATA  --------------------------- //

// GetNodeMeta returns just the node-level metadata (no Pods loaded). Use
// GetNode for an assembled view that includes the per-pod records.
func (s *CacheStore) GetNodeMeta(ctx context.Context, nodeName string) (*NodeRecord, bool, int64, error) {
	item, found, err := s.store.Get(ctx, cacheNodePK, nodeName)
	if err != nil || !found {
		return nil, found, 0, err
	}
	rec, err := unmarshalNodeMeta(item.Payload)
	if err != nil {
		return nil, false, 0, err
	}
	return rec, true, item.Version, nil
}

// UpsertNodeMeta persists only the metadata fields of rec (Node, Generation,
// UpdatedAt). The rec.Pods slice is intentionally ignored — pods are stored as
// separate items via AddNodePod / RemoveNodePod.
func (s *CacheStore) UpsertNodeMeta(ctx context.Context, nodeName string, rec *NodeRecord) error {
	payload, err := marshalNodeMeta(rec)
	if err != nil {
		return err
	}
	return s.store.Upsert(ctx, cacheNodePK, nodeName, payload, nil)
}

// DeleteNodeMeta removes only the metadata item. Callers that want to fully
// drop a node (including its per-pod items) should call DeleteNode.
func (s *CacheStore) DeleteNodeMeta(ctx context.Context, nodeName string) (bool, error) {
	return s.store.Delete(ctx, cacheNodePK, nodeName)
}

// ListNodeMeta returns the metadata for every known node, without loading any
// per-pod records. Cheaper than ListNodes when the caller does not need pods.
func (s *CacheStore) ListNodeMeta(ctx context.Context) (map[string]*NodeRecord, error) {
	items, err := s.store.ListPartition(ctx, cacheNodePK)
	if err != nil {
		return nil, err
	}
	out := make(map[string]*NodeRecord, len(items))
	for _, item := range items {
		rec, err := unmarshalNodeMeta(item.Payload)
		if err != nil {
			continue
		}
		out[item.SK] = rec
	}
	return out, nil
}

// ---------------------------  NODE PODS  --------------------------- //

// AddNodePod stores (or replaces) the record for a pod assigned to nodeName.
// The pod is keyed by its UID; calling AddNodePod again for the same pod
// overwrites the existing entry, matching the semantics of "the latest version
// of this pod is what's on the node".
func (s *CacheStore) AddNodePod(ctx context.Context, nodeName string, pod *corev1.Pod) error {
	if pod == nil {
		return fmt.Errorf("nil pod")
	}
	key, err := framework.GetPodKey(pod)
	if err != nil {
		return err
	}
	payload, err := marshalNodePod(pod)
	if err != nil {
		return err
	}
	return s.store.Upsert(ctx, cacheNodePodPK(nodeName), key, payload, nil)
}

// RemoveNodePod deletes the per-node record for the given pod key. Returns
// false (without error) if the record was not present.
func (s *CacheStore) RemoveNodePod(ctx context.Context, nodeName, podKey string) (bool, error) {
	return s.store.Delete(ctx, cacheNodePodPK(nodeName), podKey)
}

// ListNodePods returns every pod currently recorded as scheduled on nodeName.
func (s *CacheStore) ListNodePods(ctx context.Context, nodeName string) ([]*corev1.Pod, error) {
	items, err := s.store.ListPartition(ctx, cacheNodePodPK(nodeName))
	if err != nil {
		return nil, err
	}
	out := make([]*corev1.Pod, 0, len(items))
	for _, item := range items {
		pod, err := unmarshalNodePod(item.Payload)
		if err != nil {
			continue
		}
		out = append(out, pod)
	}
	return out, nil
}

// CountNodePods returns the number of per-node pod records for nodeName
// without paying to load and decode each item.
func (s *CacheStore) CountNodePods(ctx context.Context, nodeName string) (int, error) {
	return s.store.CountPartition(ctx, cacheNodePodPK(nodeName))
}

// ---------------------------  ASSEMBLED NODE  --------------------------- //

// GetNode returns the node record assembled from its metadata item plus all
// per-pod items. The returned NodeRecord has Pods populated.
func (s *CacheStore) GetNode(ctx context.Context, nodeName string) (*NodeRecord, bool, int64, error) {
	rec, found, version, err := s.GetNodeMeta(ctx, nodeName)
	if err != nil || !found {
		return nil, found, 0, err
	}
	pods, err := s.ListNodePods(ctx, nodeName)
	if err != nil {
		return nil, false, 0, err
	}
	rec.Pods = pods
	return rec, true, version, nil
}

// ListNodes assembles every known node (metadata + pods).
func (s *CacheStore) ListNodes(ctx context.Context) (map[string]*NodeRecord, error) {
	metas, err := s.ListNodeMeta(ctx)
	if err != nil {
		return nil, err
	}
	for name, rec := range metas {
		pods, err := s.ListNodePods(ctx, name)
		if err != nil {
			return nil, err
		}
		rec.Pods = pods
	}
	return metas, nil
}

// DeleteNode removes the node entirely: every per-pod record under the node's
// pod partition, then the metadata item itself. The boolean reflects whether
// the metadata item existed.
func (s *CacheStore) DeleteNode(ctx context.Context, nodeName string) (bool, error) {
	pods, err := s.ListNodePods(ctx, nodeName)
	if err != nil {
		return false, err
	}
	for _, pod := range pods {
		key, err := framework.GetPodKey(pod)
		if err != nil {
			continue
		}
		if _, err := s.store.Delete(ctx, cacheNodePodPK(nodeName), key); err != nil {
			return false, fmt.Errorf("delete pod %s on node %s: %w", key, nodeName, err)
		}
	}
	return s.DeleteNodeMeta(ctx, nodeName)
}

// ---------------------------  HELPERS  --------------------------- //

func NewNodeRecord() *NodeRecord {
	return &NodeRecord{
		Pods:      []*corev1.Pod{},
		UpdatedAt: time.Now(),
	}
}
