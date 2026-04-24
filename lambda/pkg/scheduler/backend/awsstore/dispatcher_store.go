package awsstore

import "context"

const (
	dispatchJobPK       = "DISPATCH#JOB"
	dispatchPodPK       = "DISPATCH#POD"
	dispatchNamespacePK = "DISPATCH#NAMESPACE"
)

type DispatcherStore struct {
	store DynamoMap
}

func NewDispatcherStore(store DynamoMap) *DispatcherStore {
	return &DispatcherStore{store: store}
}

func (s *DispatcherStore) UpsertDispatchJob(ctx context.Context, key string, rec *DispatchJobState) error {
	payload, err := marshalJSON(rec)
	if err != nil {
		return err
	}
	return s.store.Upsert(ctx, dispatchJobPK, key, payload, nil)
}

func (s *DispatcherStore) DeleteDispatchJob(ctx context.Context, key string) (bool, error) {
	return s.store.Delete(ctx, dispatchJobPK, key)
}

func (s *DispatcherStore) ListDispatchJobs(ctx context.Context) (map[string]*DispatchJobState, error) {
	items, err := s.store.ListPartition(ctx, dispatchJobPK)
	if err != nil {
		return nil, err
	}
	out := make(map[string]*DispatchJobState, len(items))
	for _, item := range items {
		rec, err := unmarshalDispatchJobRecord(item.Payload)
		if err != nil {
			continue
		}
		out[item.SK] = rec
	}
	return out, nil
}

func (s *DispatcherStore) UpsertDispatchPod(ctx context.Context, key string, rec *DispatchPodState) error {
	payload, err := marshalJSON(rec)
	if err != nil {
		return err
	}
	return s.store.Upsert(ctx, dispatchPodPK, key, payload, nil)
}

func (s *DispatcherStore) DeleteDispatchPod(ctx context.Context, key string) (bool, error) {
	return s.store.Delete(ctx, dispatchPodPK, key)
}

func (s *DispatcherStore) ListDispatchPods(ctx context.Context) (map[string]*DispatchPodState, error) {
	items, err := s.store.ListPartition(ctx, dispatchPodPK)
	if err != nil {
		return nil, err
	}
	out := make(map[string]*DispatchPodState, len(items))
	for _, item := range items {
		rec, err := unmarshalDispatchPodRecord(item.Payload)
		if err != nil {
			continue
		}
		out[item.SK] = rec
	}
	return out, nil
}

func (s *DispatcherStore) UpsertDispatchNamespace(ctx context.Context, key string, rec *DispatchNamespaceState) error {
	payload, err := marshalJSON(rec)
	if err != nil {
		return err
	}
	return s.store.Upsert(ctx, dispatchNamespacePK, key, payload, nil)
}

func (s *DispatcherStore) DeleteDispatchNamespace(ctx context.Context, key string) (bool, error) {
	return s.store.Delete(ctx, dispatchNamespacePK, key)
}

func (s *DispatcherStore) ListDispatchNamespaces(ctx context.Context) (map[string]*DispatchNamespaceState, error) {
	items, err := s.store.ListPartition(ctx, dispatchNamespacePK)
	if err != nil {
		return nil, err
	}
	out := make(map[string]*DispatchNamespaceState, len(items))
	for _, item := range items {
		rec, err := unmarshalDispatchNamespaceRecord(item.Payload)
		if err != nil {
			continue
		}
		out[item.SK] = rec
	}
	return out, nil
}
