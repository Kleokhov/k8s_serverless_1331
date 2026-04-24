package awsstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	v1 "k8s.io/api/core/v1"
	"k8s.io/kubernetes/pkg/scheduler/framework"
)

type BackoffQueuesAWS struct {
	client         *dynamodb.Client
	tableName      string
	backoffQ       *dynamoQueueStore
	errorBackoffQ  *dynamoQueueStore
	getBackoffTime BackoffTimeFunc
	now            func() time.Time
}

func NewBackoffQueueFromEnv(env *DynamoQueueEnv, getBackoffTime BackoffTimeFunc) (*dynamoQueueStore, error) {
	if env == nil || env.Client == nil || env.TableName == "" {
		return nil, fmt.Errorf("invalid DynamoQueueEnv")
	}
	if getBackoffTime == nil {
		return nil, fmt.Errorf("getBackoffTime is required for backoffQ")
	}

	return newDynamoQueueStore(
		env.Client,
		env.TableName,
		QueueBackoff,
		func(pInfo *framework.QueuedPodInfo) (string, error) {
			return encodeBackoffOrderKey(getBackoffTime(pInfo), pInfo.Pod.UID), nil
		},
		func(pInfo *framework.QueuedPodInfo) (map[string]dbtypes.AttributeValue, error) {
			bo := getBackoffTime(pInfo)
			return map[string]dbtypes.AttributeValue{
				AttrBackoffCompletes: avN(bo.UnixMilli()),
			}, nil
		},
	), nil
}

func NewErrorBackoffQueueFromEnv(env *DynamoQueueEnv, getBackoffTime BackoffTimeFunc) (*dynamoQueueStore, error) {
	if env == nil || env.Client == nil || env.TableName == "" {
		return nil, fmt.Errorf("invalid DynamoQueueEnv")
	}
	if getBackoffTime == nil {
		return nil, fmt.Errorf("getBackoffTime is required for errorBackoffQ")
	}

	return newDynamoQueueStore(
		env.Client,
		env.TableName,
		QueueErrorBackoff,
		func(pInfo *framework.QueuedPodInfo) (string, error) {
			return encodeErrorBackoffOrderKey(getBackoffTime(pInfo), pInfo.Pod.UID), nil
		},
		func(pInfo *framework.QueuedPodInfo) (map[string]dbtypes.AttributeValue, error) {
			bo := getBackoffTime(pInfo)
			return map[string]dbtypes.AttributeValue{
				AttrBackoffCompletes: avN(bo.UnixMilli()),
			}, nil
		},
	), nil
}

func NewBackoffQueuesFromEnv(env *DynamoQueueEnv, getBackoffTime BackoffTimeFunc) (*BackoffQueuesAWS, error) {
	backoffStore, err := NewBackoffQueueFromEnv(env, getBackoffTime)
	if err != nil {
		return nil, err
	}
	errorBackoffStore, err := NewErrorBackoffQueueFromEnv(env, getBackoffTime)
	if err != nil {
		return nil, err
	}

	if getBackoffTime == nil {
		return nil, fmt.Errorf("getBackoffTime is required for backoff queues")
	}

	return &BackoffQueuesAWS{
		client:         env.Client,
		tableName:      env.TableName,
		backoffQ:       backoffStore,
		errorBackoffQ:  errorBackoffStore,
		getBackoffTime: getBackoffTime,
		now:            time.Now,
	}, nil
}

// ---------------------------  ADD  --------------------------- //

func (bq *BackoffQueuesAWS) Add(ctx context.Context, pInfo *framework.QueuedPodInfo) error {
	if pInfo == nil || pInfo.Pod == nil || pInfo.PodInfo == nil {
		return fmt.Errorf("nil pod")
	}

	target := bq.backoffQ
	sibling := bq.errorBackoffQ
	if shouldUseErrorBackoffQ(pInfo) {
		target = bq.errorBackoffQ
		sibling = bq.backoffQ
	}

	for {
		cur, found, err := target.getStoredItem(ctx, pInfo.Pod.UID)
		if err != nil {
			return err
		}

		version := int64(1)
		condExpr := "attribute_not_exists(#pk) AND attribute_not_exists(#sk)"
		exprNames := map[string]string{
			"#pk": AttrPK,
			"#sk": AttrSK,
		}
		exprVals := map[string]dbtypes.AttributeValue{}

		if found {
			version = cur.Version + 1
			condExpr = "#v = :expected"
			exprNames = map[string]string{
				"#v": AttrVersion,
			}
			exprVals = map[string]dbtypes.AttributeValue{
				":expected": avN(cur.Version),
			}
			if pInfo.Timestamp.IsZero() {
				pInfo.Timestamp = cur.PInfo.Timestamp
			}
		} else if pInfo.Timestamp.IsZero() {
			pInfo.Timestamp = target.now()
		}

		item, err := target.prepareItem(pInfo, version)
		if err != nil {
			return err
		}

		_, err = bq.client.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
			TransactItems: []dbtypes.TransactWriteItem{
				{
					Put: &dbtypes.Put{
						TableName:                 aws.String(bq.tableName),
						Item:                      item,
						ConditionExpression:       aws.String(condExpr),
						ExpressionAttributeNames:  exprNames,
						ExpressionAttributeValues: exprVals,
					},
				},
				{
					Delete: &dbtypes.Delete{
						TableName: aws.String(bq.tableName),
						Key: map[string]dbtypes.AttributeValue{
							AttrPK: avS(string(sibling.queueID)),
							AttrSK: avS(string(pInfo.Pod.UID)),
						},
					},
				},
			},
		})
		if isConditionalFailure(err) {
			continue
		}
		return err
	}
}

// ---------------------------  UPDATE  --------------------------- //

func (bq *BackoffQueuesAWS) Update(
	ctx context.Context,
	newPod *v1.Pod,
	oldPodInfo *framework.QueuedPodInfo,
) (*framework.QueuedPodInfo, error) {
	if p, err := (&ActiveQueueAWS{store: bq.backoffQ}).Update(ctx, newPod, oldPodInfo); err != nil || p != nil {
		return p, err
	}
	return (&ActiveQueueAWS{store: bq.errorBackoffQ}).Update(ctx, newPod, oldPodInfo)
}

func shouldUseErrorBackoffQ(pInfo *framework.QueuedPodInfo) bool {
	return pInfo.UnschedulablePlugins.Len() == 0 && pInfo.PendingPlugins.Len() == 0
}

// ---------------------------  DELETE  --------------------------- //

func (bq *BackoffQueuesAWS) Delete(ctx context.Context, pInfo *framework.QueuedPodInfo) (bool, error) {
	if pInfo == nil || pInfo.Pod == nil {
		return false, fmt.Errorf("nil pod")
	}

	deleted, err := bq.backoffQ.deleteIfPresent(ctx, pInfo.Pod.UID)
	if err != nil {
		return false, fmt.Errorf("error deleting from backoffQ: %w", err)
	}
	if deleted {
		return true, nil
	}

	deleted, err = bq.errorBackoffQ.deleteIfPresent(ctx, pInfo.Pod.UID)
	if err != nil {
		return false, fmt.Errorf("error deleting from errorBackoffQ: %w", err)
	}
	return deleted, nil
}

// ---------------------------  PEEK  --------------------------- //

func (bq *BackoffQueuesAWS) Peek(ctx context.Context) (*framework.QueuedPodInfo, error) {
	return bq.backoffQ.Peek(ctx)
}

func (bq *BackoffQueuesAWS) PeekErrorBackoff(ctx context.Context) (*framework.QueuedPodInfo, error) {
	return bq.errorBackoffQ.Peek(ctx)
}

// ---------------------------  POP  --------------------------- //

func (bq *BackoffQueuesAWS) Pop(ctx context.Context) (*framework.QueuedPodInfo, error) {
	return bq.backoffQ.Pop(ctx)
}

func (bq *BackoffQueuesAWS) PopErrorBackoff(ctx context.Context) (*framework.QueuedPodInfo, error) {
	return bq.errorBackoffQ.Pop(ctx)
}

// ---------------------------  GET  --------------------------- //

func (bq *BackoffQueuesAWS) Get(
	ctx context.Context,
	lookup *framework.QueuedPodInfo,
) (*framework.QueuedPodInfo, bool, error) {
	if lookup == nil || lookup.Pod == nil {
		return nil, false, nil
	}

	if cur, found, err := bq.backoffQ.getStoredItem(ctx, lookup.Pod.UID); err != nil {
		return nil, false, err
	} else if found {
		return cur.PInfo, true, nil
	}

	if cur, found, err := bq.errorBackoffQ.getStoredItem(ctx, lookup.Pod.UID); err != nil {
		return nil, false, err
	} else if found {
		return cur.PInfo, true, nil
	}

	return nil, false, nil
}

// ---------------------------  HAS  --------------------------- //

func (bq *BackoffQueuesAWS) Has(ctx context.Context, pInfo *framework.QueuedPodInfo) (bool, error) {
	_, found, err := bq.Get(ctx, pInfo)
	return found, err
}

// ---------------------------  LIST  --------------------------- //

func (bq *BackoffQueuesAWS) List(ctx context.Context) ([]*framework.QueuedPodInfo, error) {
	backoffItems, err := bq.backoffQ.List(ctx)
	if err != nil {
		return nil, err
	}
	errorItems, err := bq.errorBackoffQ.List(ctx)
	if err != nil {
		return nil, err
	}

	out := make([]*framework.QueuedPodInfo, 0, len(backoffItems)+len(errorItems))
	out = append(out, backoffItems...)
	out = append(out, errorItems...)
	return out, nil
}

func (bq *BackoffQueuesAWS) ListPods(ctx context.Context) ([]*v1.Pod, error) {
	items, err := bq.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*v1.Pod, 0, len(items))
	for _, pInfo := range items {
		out = append(out, pInfo.Pod)
	}
	return out, nil
}

// ---------------------------  LEN  --------------------------- //

func (bq *BackoffQueuesAWS) Len(ctx context.Context) (int, error) {
	n1, err := bq.backoffQ.Len(ctx)
	if err != nil {
		return 0, err
	}
	n2, err := bq.errorBackoffQ.Len(ctx)
	if err != nil {
		return 0, err
	}
	return n1 + n2, nil
}

func (bq *BackoffQueuesAWS) LenBackoff(ctx context.Context) (int, error) {
	return bq.backoffQ.Len(ctx)
}

// ---------------------------  UTILS  --------------------------- //

func (bq *BackoffQueuesAWS) isPodBackingOff(pInfo *framework.QueuedPodInfo) bool {
	if pInfo == nil {
		return false
	}
	boTime := bq.getBackoffTime(pInfo)
	return !boTime.Before(bq.now())
}

func (bq *BackoffQueuesAWS) popAllBackoffCompletedFromStore(
	ctx context.Context,
	store *dynamoQueueStore,
) ([]*framework.QueuedPodInfo, error) {
	var out []*framework.QueuedPodInfo

	for {
		cur, err := store.peekHeadStored(ctx)
		if errors.Is(err, ErrQueueEmpty) {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		if bq.isPodBackingOff(cur.PInfo) {
			return out, nil
		}

		deleted, err := store.deleteIfVersion(ctx, cur.PInfo.Pod.UID, cur.Version)
		if err != nil {
			return out, err
		}
		if !deleted {
			// Head changed after peek; retry.
			continue
		}

		out = append(out, cur.PInfo)
	}
}

func (bq *BackoffQueuesAWS) PopAllBackoffCompleted(
	ctx context.Context,
) ([]*framework.QueuedPodInfo, error) {
	backoffReady, err := bq.popAllBackoffCompletedFromStore(ctx, bq.backoffQ)
	if err != nil {
		return nil, err
	}
	errorReady, err := bq.popAllBackoffCompletedFromStore(ctx, bq.errorBackoffQ)
	if err != nil {
		return nil, err
	}
	return append(backoffReady, errorReady...), nil
}
