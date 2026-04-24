package awsstore

import (
	"context"

	dbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	v1 "k8s.io/api/core/v1"
	"k8s.io/kubernetes/pkg/scheduler/framework"
)

type ActiveQueue interface {
	Add(ctx context.Context, pInfo *framework.QueuedPodInfo) error
	Update(ctx context.Context, newPod *v1.Pod, oldPodInfo *framework.QueuedPodInfo) (*framework.QueuedPodInfo, error)
	Delete(ctx context.Context, pInfo *framework.QueuedPodInfo) error
	Peek(ctx context.Context) (*framework.QueuedPodInfo, error)
	Pop(ctx context.Context) (*framework.QueuedPodInfo, error) // non-blocking
	Get(ctx context.Context, lookup *framework.QueuedPodInfo) (*framework.QueuedPodInfo, bool, error)
	List(ctx context.Context) ([]*framework.QueuedPodInfo, error)
	Len(ctx context.Context) (int, error)
	Has(ctx context.Context, pInfo *framework.QueuedPodInfo) (bool, error)
}

type BackoffQueue interface {
	Add(ctx context.Context, pInfo *framework.QueuedPodInfo) error
	Update(ctx context.Context, newPod *v1.Pod, oldPodInfo *framework.QueuedPodInfo) (*framework.QueuedPodInfo, error)
	Delete(ctx context.Context, pInfo *framework.QueuedPodInfo) (bool, error)
	Peek(ctx context.Context) (*framework.QueuedPodInfo, error)
	Pop(ctx context.Context) (*framework.QueuedPodInfo, error)
	Get(ctx context.Context, lookup *framework.QueuedPodInfo) (*framework.QueuedPodInfo, bool, error)
	Has(ctx context.Context, pInfo *framework.QueuedPodInfo) (bool, error)
	List(ctx context.Context) ([]*framework.QueuedPodInfo, error)
	Len(ctx context.Context) (int, error)
	LenBackoff(ctx context.Context) (int, error)
	PopAllBackoffCompleted(ctx context.Context) ([]*framework.QueuedPodInfo, error)
}

type DynamoMap interface {
	Get(ctx context.Context, pk, sk string) (*MapItem, bool, error)
	Upsert(ctx context.Context, pk, sk string, payload []byte, extra map[string]dbtypes.AttributeValue) error
	Delete(ctx context.Context, pk, sk string) (bool, error)
	DeleteIfVersion(ctx context.Context, pk, sk string, expectedVersion int64) (bool, error)
	ListPartition(ctx context.Context, pk string) ([]*MapItem, error)
	CountPartition(ctx context.Context, pk string) (int, error)
	PutTx(pk, sk string, payload []byte, extra map[string]dbtypes.AttributeValue) dbtypes.TransactWriteItem
	DeleteTx(pk, sk string) dbtypes.TransactWriteItem
	TransactWrite(ctx context.Context, items []dbtypes.TransactWriteItem) error
}
