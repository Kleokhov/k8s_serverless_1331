package awsstore

import (
	"context"
	"fmt"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/kubernetes/pkg/scheduler/framework"
)

type ActiveQueueAWS struct {
	store *dynamoQueueStore
}

func NewActiveQueueFromEnv(env *DynamoQueueEnv) (*ActiveQueueAWS, error) {
	if env == nil || env.Client == nil || env.TableName == "" {
		return nil, fmt.Errorf("invalid DynamoQueueEnv")
	}

	store := newDynamoQueueStore(
		env.Client,
		env.TableName,
		QueueActive,
		func(pInfo *framework.QueuedPodInfo) (string, error) {
			return encodeActiveOrderKey(pInfo), nil
		},
		nil,
	)

	return &ActiveQueueAWS{store: store}, nil
}

// ---------------------------  ADD  --------------------------- //

func (q *ActiveQueueAWS) Add(ctx context.Context, pInfo *framework.QueuedPodInfo) error {
	if pInfo == nil || pInfo.Pod == nil || pInfo.PodInfo == nil {
		return fmt.Errorf("nil pod")
	}

	for {
		cur, found, err := q.store.getStoredItem(ctx, pInfo.Pod.UID)
		if err != nil {
			return err
		}

		if !found {
			if pInfo.Timestamp.IsZero() {
				pInfo.Timestamp = q.store.now()
			}
			item, err := q.store.prepareItem(pInfo, 1)
			if err != nil {
				return err
			}
			err = q.store.putIfAbsent(ctx, item)
			if isConditionalFailure(err) {
				continue
			}
			return err
		}

		// Replace existing keyed entry. Preserve queue-entry timestamp
		// if caller didn't explicitly set one.
		if pInfo.Timestamp.IsZero() {
			pInfo.Timestamp = cur.PInfo.Timestamp
		}

		item, err := q.store.prepareItem(pInfo, cur.Version+1)
		if err != nil {
			return err
		}
		err = q.store.putIfVersion(ctx, item, cur.Version)
		if isConditionalFailure(err) {
			continue
		}
		return err
	}
}

// ---------------------------  UPDATE  --------------------------- //

func (q *ActiveQueueAWS) Update(
	ctx context.Context,
	newPod *v1.Pod,
	oldPodInfo *framework.QueuedPodInfo,
) (*framework.QueuedPodInfo, error) {
	if newPod == nil || oldPodInfo == nil || oldPodInfo.Pod == nil {
		return nil, fmt.Errorf("nil pod")
	}

	for {
		cur, found, err := q.store.getStoredItem(ctx, oldPodInfo.Pod.UID)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, nil
		}

		next := cur.PInfo
		if err := next.Update(newPod); err != nil {
			return nil, err
		}
		// Important: keep existing Timestamp. That preserves activeQ ordering.

		item, err := q.store.prepareItem(next, cur.Version+1)
		if err != nil {
			return nil, err
		}

		err = q.store.putIfVersion(ctx, item, cur.Version)
		if isConditionalFailure(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return next, nil
	}
}

// ---------------------------  DELETE  --------------------------- //

func (q *ActiveQueueAWS) Delete(ctx context.Context, pInfo *framework.QueuedPodInfo) error {
	if pInfo == nil || pInfo.Pod == nil {
		return fmt.Errorf("nil pod")
	}

	deleted, err := q.store.deleteIfPresent(ctx, pInfo.Pod.UID)
	if err != nil {
		return err
	}
	if !deleted {
		return ErrQueueNotFound
	}
	return nil
}

// ---------------------------  PEEK  --------------------------- //

func (q *ActiveQueueAWS) Peek(ctx context.Context) (*framework.QueuedPodInfo, error) {
	return q.store.Peek(ctx)
}

// ---------------------------  POP  --------------------------- //

func (q *ActiveQueueAWS) Pop(ctx context.Context) (*framework.QueuedPodInfo, error) {
	pInfo, err := q.store.Pop(ctx)
	if err != nil {
		return nil, err
	}

	pInfo.Attempts++
	pInfo.BackoffExpiration = time.Time{}
	pInfo.UnschedulablePlugins.Clear()
	pInfo.PendingPlugins.Clear()
	return pInfo, nil
}

// ---------------------------  GET  --------------------------- //

func (q *ActiveQueueAWS) Get(
	ctx context.Context,
	lookup *framework.QueuedPodInfo,
) (*framework.QueuedPodInfo, bool, error) {
	if lookup == nil || lookup.Pod == nil {
		return nil, false, nil
	}

	cur, found, err := q.store.getStoredItem(ctx, lookup.Pod.UID)
	if err != nil || !found {
		return nil, found, err
	}
	return cur.PInfo, true, nil
}

// ---------------------------  HAS  --------------------------- //

func (q *ActiveQueueAWS) Has(ctx context.Context, lookup *framework.QueuedPodInfo) (bool, error) {
	_, found, err := q.Get(ctx, lookup)
	return found, err
}

// ---------------------------  LIST  --------------------------- //

func (q *ActiveQueueAWS) List(ctx context.Context) ([]*framework.QueuedPodInfo, error) {
	return q.store.List(ctx)
}

func (q *ActiveQueueAWS) ListPods(ctx context.Context) ([]*v1.Pod, error) {
	pInfos, err := q.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*v1.Pod, 0, len(pInfos))
	for _, pInfo := range pInfos {
		out = append(out, pInfo.Pod)
	}
	return out, nil
}

// ---------------------------  LEN  --------------------------- //

func (q *ActiveQueueAWS) Len(ctx context.Context) (int, error) {
	return q.store.Len(ctx)
}
