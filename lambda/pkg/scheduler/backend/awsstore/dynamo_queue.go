package awsstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	ktypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/kubernetes/pkg/scheduler/framework"
)

type QueueID string

const (
	QueueActive       QueueID = "activeQ"
	QueueBackoff      QueueID = "backoffQ"
	QueueErrorBackoff QueueID = "errorBackoffQ"
)

const (
	AttrPK               = "PK"
	AttrSK               = "SK"
	AttrOrderKey         = "OrderKey"
	AttrVersion          = "Version"
	AttrPayload          = "Payload"
	AttrTimestamp        = "Timestamp"
	AttrPriority         = "Priority"
	AttrAttempts         = "Attempts"
	AttrBackoffCompletes = "BackoffCompletes"

	OrderIndexName = "OrderIndex"
)

type BackoffTimeFunc func(*framework.QueuedPodInfo) time.Time

type orderKeyBuilder func(*framework.QueuedPodInfo) (string, error)
type extraAttrsBuilder func(*framework.QueuedPodInfo) (map[string]dbtypes.AttributeValue, error)

type dynamoQueueStore struct {
	client    *dynamodb.Client
	tableName string
	queueID   QueueID
	now       func() time.Time

	buildOrderKey   orderKeyBuilder
	buildExtraAttrs extraAttrsBuilder
}

func newDynamoQueueStore(
	client *dynamodb.Client,
	tableName string,
	queueID QueueID,
	buildOrderKey orderKeyBuilder,
	buildExtraAttrs extraAttrsBuilder,
) *dynamoQueueStore {
	if buildExtraAttrs == nil {
		buildExtraAttrs = func(*framework.QueuedPodInfo) (map[string]dbtypes.AttributeValue, error) {
			return nil, nil
		}
	}

	return &dynamoQueueStore{
		client:          client,
		tableName:       tableName,
		queueID:         queueID,
		now:             time.Now,
		buildOrderKey:   buildOrderKey,
		buildExtraAttrs: buildExtraAttrs,
	}
}

type DynamoQueueEnv struct {
	Client    *dynamodb.Client
	TableName string
}

func NewDynamoQueueEnvFromClient(
	ctx context.Context,
	client *dynamodb.Client,
	tableName string,
) (*DynamoQueueEnv, error) {
	if client == nil {
		return nil, fmt.Errorf("nil dynamodb client")
	}
	if tableName == "" {
		return nil, fmt.Errorf("empty table name")
	}

	if err := ensureDynamoTable(ctx, client, tableName); err != nil {
		return nil, err
	}

	return &DynamoQueueEnv{
		Client:    client,
		TableName: tableName,
	}, nil
}

func ensureDynamoTable(ctx context.Context, ddb *dynamodb.Client, tableName string) error {
	if _, err := ddb.DescribeTable(ctx, &dynamodb.DescribeTableInput{
		TableName: aws.String(tableName),
	}); err == nil {
		return nil
	} else {
		var rnfe *dbtypes.ResourceNotFoundException
		if !errors.As(err, &rnfe) {
			return err
		}
	}

	_, err := ddb.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName: aws.String(tableName),
		AttributeDefinitions: []dbtypes.AttributeDefinition{
			{AttributeName: aws.String(AttrPK), AttributeType: dbtypes.ScalarAttributeTypeS},
			{AttributeName: aws.String(AttrSK), AttributeType: dbtypes.ScalarAttributeTypeS},
			{AttributeName: aws.String(AttrOrderKey), AttributeType: dbtypes.ScalarAttributeTypeS},
		},
		KeySchema: []dbtypes.KeySchemaElement{
			{AttributeName: aws.String(AttrPK), KeyType: dbtypes.KeyTypeHash},
			{AttributeName: aws.String(AttrSK), KeyType: dbtypes.KeyTypeRange},
		},
		GlobalSecondaryIndexes: []dbtypes.GlobalSecondaryIndex{
			{
				IndexName: aws.String(OrderIndexName),
				KeySchema: []dbtypes.KeySchemaElement{
					{AttributeName: aws.String(AttrPK), KeyType: dbtypes.KeyTypeHash},
					{AttributeName: aws.String(AttrOrderKey), KeyType: dbtypes.KeyTypeRange},
				},
				Projection: &dbtypes.Projection{
					ProjectionType: dbtypes.ProjectionTypeAll,
				},
			},
		},
		BillingMode: dbtypes.BillingModePayPerRequest,
	})
	return err
}

// ---------------------------  ADD  --------------------------- //

type storedItem struct {
	PInfo   *framework.QueuedPodInfo
	Version int64
}

func (store *dynamoQueueStore) prepareItem(
	pInfo *framework.QueuedPodInfo,
	version int64,
) (map[string]dbtypes.AttributeValue, error) {
	if pInfo == nil || pInfo.Pod == nil || pInfo.PodInfo == nil {
		return nil, fmt.Errorf("nil pod")
	}
	if pInfo.Timestamp.IsZero() {
		pInfo.Timestamp = store.now()
	}

	orderKey, err := store.buildOrderKey(pInfo)
	if err != nil {
		return nil, err
	}

	extraAttrs, err := store.buildExtraAttrs(pInfo)
	if err != nil {
		return nil, err
	}

	payload, err := MarshalQueuedPodInfo(pInfo)
	if err != nil {
		return nil, fmt.Errorf("marshal pod: %w", err)
	}

	item := map[string]dbtypes.AttributeValue{
		AttrPK:        avS(string(store.queueID)),
		AttrSK:        avS(string(pInfo.Pod.UID)),
		AttrOrderKey:  avS(orderKey),
		AttrVersion:   avN(version),
		AttrTimestamp: avN(pInfo.Timestamp.UnixMilli()),
		AttrPriority:  avN(int64(priorityOf(pInfo))),
		AttrAttempts:  avN(int64(pInfo.Attempts)),
		AttrPayload:   avB(payload),
	}

	for k, v := range extraAttrs {
		item[k] = v
	}
	return item, nil
}

// ---------------------------  UPDATE  --------------------------- //

func (store *dynamoQueueStore) getStoredItem(
	ctx context.Context,
	uid ktypes.UID,
) (*storedItem, bool, error) {
	out, err := store.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(store.tableName),
		Key: map[string]dbtypes.AttributeValue{
			AttrPK: avS(string(store.queueID)),
			AttrSK: avS(string(uid)),
		},
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, false, err
	}
	if len(out.Item) == 0 {
		return nil, false, nil
	}

	cur, err := decodeStoredItem(out.Item)
	if err != nil {
		return nil, false, err
	}
	return cur, true, nil
}

func decodeStoredItem(item map[string]dbtypes.AttributeValue) (*storedItem, error) {
	payloadAttr, ok := item[AttrPayload].(*dbtypes.AttributeValueMemberB)
	if !ok {
		return nil, fmt.Errorf("item missing payload")
	}
	pInfo, err := UnmarshalQueuedPodInfo(payloadAttr.Value)
	if err != nil {
		return nil, fmt.Errorf("unmarshal payload: %w", err)
	}

	version, err := parseInt64Attr(item, AttrVersion)
	if err != nil {
		return nil, err
	}

	return &storedItem{
		PInfo:   pInfo,
		Version: version,
	}, nil
}

func (store *dynamoQueueStore) putIfAbsent(
	ctx context.Context,
	item map[string]dbtypes.AttributeValue,
) error {
	_, err := store.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(store.tableName),
		Item:      item,
		ConditionExpression: aws.String(
			"attribute_not_exists(#pk) AND attribute_not_exists(#sk)",
		),
		ExpressionAttributeNames: map[string]string{
			"#pk": AttrPK,
			"#sk": AttrSK,
		},
	})
	return err
}

func (store *dynamoQueueStore) putIfVersion(
	ctx context.Context,
	item map[string]dbtypes.AttributeValue,
	expectedVersion int64,
) error {
	_, err := store.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(store.tableName),
		Item:                item,
		ConditionExpression: aws.String("#v = :expected"),
		ExpressionAttributeNames: map[string]string{
			"#v": AttrVersion,
		},
		ExpressionAttributeValues: map[string]dbtypes.AttributeValue{
			":expected": avN(expectedVersion),
		},
	})
	return err
}

// ---------------------------  DELETE  --------------------------- //

func (store *dynamoQueueStore) deleteIfPresent(
	ctx context.Context,
	uid ktypes.UID,
) (bool, error) {
	_, err := store.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(store.tableName),
		Key: map[string]dbtypes.AttributeValue{
			AttrPK: avS(string(store.queueID)),
			AttrSK: avS(string(uid)),
		},
		ConditionExpression: aws.String("attribute_exists(#pk) AND attribute_exists(#sk)"),
		ExpressionAttributeNames: map[string]string{
			"#pk": AttrPK,
			"#sk": AttrSK,
		},
	})
	if isConditionalFailure(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (store *dynamoQueueStore) deleteIfVersion(
	ctx context.Context,
	uid ktypes.UID,
	expectedVersion int64,
) (bool, error) {
	_, err := store.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(store.tableName),
		Key: map[string]dbtypes.AttributeValue{
			AttrPK: avS(string(store.queueID)),
			AttrSK: avS(string(uid)),
		},
		ConditionExpression: aws.String("#v = :expected"),
		ExpressionAttributeNames: map[string]string{
			"#v": AttrVersion,
		},
		ExpressionAttributeValues: map[string]dbtypes.AttributeValue{
			":expected": avN(expectedVersion),
		},
	})
	if isConditionalFailure(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// ---------------------------  PEEK  --------------------------- //

func (store *dynamoQueueStore) peekHeadStored(ctx context.Context) (*storedItem, error) {
	out, err := store.client.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(store.tableName),
		IndexName:              aws.String(OrderIndexName),
		KeyConditionExpression: aws.String("#pk = :pk"),
		ExpressionAttributeNames: map[string]string{
			"#pk": AttrPK,
		},
		ExpressionAttributeValues: map[string]dbtypes.AttributeValue{
			":pk": avS(string(store.queueID)),
		},
		ScanIndexForward: aws.Bool(true),
		Limit:            aws.Int32(1),
	})
	if err != nil {
		return nil, err
	}
	if len(out.Items) == 0 {
		return nil, ErrQueueEmpty
	}

	return decodeStoredItem(out.Items[0])
}

func (store *dynamoQueueStore) Peek(ctx context.Context) (*framework.QueuedPodInfo, error) {
	cur, err := store.peekHeadStored(ctx)
	if err != nil {
		return nil, err
	}
	return cur.PInfo, nil
}

// --------------------------- POP  --------------------------- //

func (store *dynamoQueueStore) Pop(ctx context.Context) (*framework.QueuedPodInfo, error) {
	for {
		cur, err := store.peekHeadStored(ctx)
		if err != nil {
			return nil, err
		}

		deleted, err := store.deleteIfVersion(ctx, cur.PInfo.Pod.UID, cur.Version)
		if err != nil {
			return nil, err
		}
		if !deleted {
			// Head changed between Query and Delete; retry.
			continue
		}
		return cur.PInfo, nil
	}
}

// --------------------------- LIST  --------------------------- //

func (store *dynamoQueueStore) List(ctx context.Context) ([]*framework.QueuedPodInfo, error) {
	var out []*framework.QueuedPodInfo
	var startKey map[string]dbtypes.AttributeValue

	for {
		resp, err := store.client.Query(ctx, &dynamodb.QueryInput{
			TableName:              aws.String(store.tableName),
			KeyConditionExpression: aws.String("#pk = :pk"),
			ExpressionAttributeNames: map[string]string{
				"#pk": AttrPK,
			},
			ExpressionAttributeValues: map[string]dbtypes.AttributeValue{
				":pk": avS(string(store.queueID)),
			},
			ConsistentRead:    aws.Bool(true),
			ExclusiveStartKey: startKey,
		})
		if err != nil {
			return nil, err
		}

		for _, item := range resp.Items {
			cur, err := decodeStoredItem(item)
			if err != nil {
				return nil, err
			}
			out = append(out, cur.PInfo)
		}

		if len(resp.LastEvaluatedKey) == 0 {
			break
		}
		startKey = resp.LastEvaluatedKey
	}

	return out, nil
}

// --------------------------- LEN  --------------------------- //

func (store *dynamoQueueStore) Len(ctx context.Context) (int, error) {
	resp, err := store.client.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(store.tableName),
		KeyConditionExpression: aws.String("#pk = :pk"),
		ExpressionAttributeNames: map[string]string{
			"#pk": AttrPK,
		},
		ExpressionAttributeValues: map[string]dbtypes.AttributeValue{
			":pk": avS(string(store.queueID)),
		},
		ConsistentRead: aws.Bool(true),
		Select:         dbtypes.SelectCount,
	})
	if err != nil {
		return 0, err
	}
	return int(resp.Count), nil
}
