package awsstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

const (
	MapAttrPK      = "PK"
	MapAttrSK      = "SK"
	MapAttrPayload = "Payload"
	MapAttrVersion = "Version"
)

type DynamoMapEnv struct {
	Client    *dynamodb.Client
	TableName string
}

type MapItem struct {
	PK      string
	SK      string
	Payload []byte
	Version int64
	Item    map[string]dbtypes.AttributeValue
}

type dynamoMapStore struct {
	client    *dynamodb.Client
	tableName string
}

func NewDynamoMapEnvFromClient(
	ctx context.Context,
	client *dynamodb.Client,
	tableName string,
) (*DynamoMapEnv, error) {
	if client == nil {
		return nil, fmt.Errorf("nil dynamodb client")
	}
	if tableName == "" {
		return nil, fmt.Errorf("empty map table name")
	}
	if err := ensureDynamoMapTable(ctx, client, tableName); err != nil {
		return nil, err
	}
	return &DynamoMapEnv{
		Client:    client,
		TableName: tableName,
	}, nil
}

func NewDynamoMapStore(env *DynamoMapEnv) DynamoMap {
	return &dynamoMapStore{
		client:    env.Client,
		tableName: env.TableName,
	}
}

func ensureDynamoMapTable(ctx context.Context, ddb *dynamodb.Client, tableName string) error {
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
			{AttributeName: aws.String(MapAttrPK), AttributeType: dbtypes.ScalarAttributeTypeS},
			{AttributeName: aws.String(MapAttrSK), AttributeType: dbtypes.ScalarAttributeTypeS},
		},
		KeySchema: []dbtypes.KeySchemaElement{
			{AttributeName: aws.String(MapAttrPK), KeyType: dbtypes.KeyTypeHash},
			{AttributeName: aws.String(MapAttrSK), KeyType: dbtypes.KeyTypeRange},
		},
		BillingMode: dbtypes.BillingModePayPerRequest,
	})
	return err
}

func (s *dynamoMapStore) buildItem(
	pk, sk string,
	payload []byte,
	version int64,
	extra map[string]dbtypes.AttributeValue,
) map[string]dbtypes.AttributeValue {
	item := map[string]dbtypes.AttributeValue{
		MapAttrPK:      avS(pk),
		MapAttrSK:      avS(sk),
		MapAttrPayload: avB(payload),
		MapAttrVersion: avN(version),
	}
	for k, v := range extra {
		item[k] = v
	}
	return item
}

func decodeMapItem(item map[string]dbtypes.AttributeValue) (*MapItem, error) {
	pkAttr, ok := item[MapAttrPK].(*dbtypes.AttributeValueMemberS)
	if !ok {
		return nil, fmt.Errorf("item missing PK")
	}
	skAttr, ok := item[MapAttrSK].(*dbtypes.AttributeValueMemberS)
	if !ok {
		return nil, fmt.Errorf("item missing SK")
	}
	payloadAttr, ok := item[MapAttrPayload].(*dbtypes.AttributeValueMemberB)
	if !ok {
		return nil, fmt.Errorf("item missing payload")
	}
	version, err := parseInt64Attr(item, MapAttrVersion)
	if err != nil {
		return nil, err
	}

	return &MapItem{
		PK:      pkAttr.Value,
		SK:      skAttr.Value,
		Payload: payloadAttr.Value,
		Version: version,
		Item:    item,
	}, nil
}

func (s *dynamoMapStore) Get(ctx context.Context, pk, sk string) (*MapItem, bool, error) {
	out, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.tableName),
		Key: map[string]dbtypes.AttributeValue{
			MapAttrPK: avS(pk),
			MapAttrSK: avS(sk),
		},
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, false, err
	}
	if len(out.Item) == 0 {
		return nil, false, nil
	}

	item, err := decodeMapItem(out.Item)
	if err != nil {
		return nil, false, err
	}
	return item, true, nil
}

func (s *dynamoMapStore) putIfAbsent(
	ctx context.Context,
	pk, sk string,
	payload []byte,
	extra map[string]dbtypes.AttributeValue,
) error {
	item := s.buildItem(pk, sk, payload, 1, extra)

	_, err := s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(s.tableName),
		Item:      item,
		ConditionExpression: aws.String(
			"attribute_not_exists(#pk) AND attribute_not_exists(#sk)",
		),
		ExpressionAttributeNames: map[string]string{
			"#pk": MapAttrPK,
			"#sk": MapAttrSK,
		},
	})
	return err
}

func (s *dynamoMapStore) putIfVersion(
	ctx context.Context,
	pk, sk string,
	payload []byte,
	expectedVersion int64,
	extra map[string]dbtypes.AttributeValue,
) error {
	item := s.buildItem(pk, sk, payload, expectedVersion+1, extra)

	_, err := s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(s.tableName),
		Item:                item,
		ConditionExpression: aws.String("#v = :expected"),
		ExpressionAttributeNames: map[string]string{
			"#v": MapAttrVersion,
		},
		ExpressionAttributeValues: map[string]dbtypes.AttributeValue{
			":expected": avN(expectedVersion),
		},
	})
	return err
}

func (s *dynamoMapStore) Upsert(
	ctx context.Context,
	pk, sk string,
	payload []byte,
	extra map[string]dbtypes.AttributeValue,
) error {
	for {
		cur, found, err := s.Get(ctx, pk, sk)
		if err != nil {
			return err
		}

		if !found {
			err = s.putIfAbsent(ctx, pk, sk, payload, extra)
			if isConditionalFailure(err) {
				continue
			}
			return err
		}

		err = s.putIfVersion(ctx, pk, sk, payload, cur.Version, extra)
		if isConditionalFailure(err) {
			continue
		}
		return err
	}
}

func (s *dynamoMapStore) Delete(ctx context.Context, pk, sk string) (bool, error) {
	_, err := s.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(s.tableName),
		Key: map[string]dbtypes.AttributeValue{
			MapAttrPK: avS(pk),
			MapAttrSK: avS(sk),
		},
		ConditionExpression: aws.String("attribute_exists(#pk) AND attribute_exists(#sk)"),
		ExpressionAttributeNames: map[string]string{
			"#pk": MapAttrPK,
			"#sk": MapAttrSK,
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

func (s *dynamoMapStore) DeleteIfVersion(
	ctx context.Context,
	pk, sk string,
	expectedVersion int64,
) (bool, error) {
	_, err := s.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(s.tableName),
		Key: map[string]dbtypes.AttributeValue{
			MapAttrPK: avS(pk),
			MapAttrSK: avS(sk),
		},
		ConditionExpression: aws.String("#v = :expected"),
		ExpressionAttributeNames: map[string]string{
			"#v": MapAttrVersion,
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

func (s *dynamoMapStore) ListPartition(ctx context.Context, pk string) ([]*MapItem, error) {
	var out []*MapItem
	var startKey map[string]dbtypes.AttributeValue

	for {
		resp, err := s.client.Query(ctx, &dynamodb.QueryInput{
			TableName:              aws.String(s.tableName),
			KeyConditionExpression: aws.String("#pk = :pk"),
			ExpressionAttributeNames: map[string]string{
				"#pk": MapAttrPK,
			},
			ExpressionAttributeValues: map[string]dbtypes.AttributeValue{
				":pk": avS(pk),
			},
			ConsistentRead:    aws.Bool(true),
			ExclusiveStartKey: startKey,
		})
		if err != nil {
			return nil, err
		}

		for _, raw := range resp.Items {
			item, err := decodeMapItem(raw)
			if err != nil {
				return nil, err
			}
			out = append(out, item)
		}

		if len(resp.LastEvaluatedKey) == 0 {
			break
		}
		startKey = resp.LastEvaluatedKey
	}

	return out, nil
}

func (s *dynamoMapStore) CountPartition(ctx context.Context, pk string) (int, error) {
	resp, err := s.client.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(s.tableName),
		KeyConditionExpression: aws.String("#pk = :pk"),
		ExpressionAttributeNames: map[string]string{
			"#pk": MapAttrPK,
		},
		ExpressionAttributeValues: map[string]dbtypes.AttributeValue{
			":pk": avS(pk),
		},
		ConsistentRead: aws.Bool(true),
		Select:         dbtypes.SelectCount,
	})
	if err != nil {
		return 0, err
	}
	return int(resp.Count), nil
}

func (s *dynamoMapStore) PutTx(
	pk, sk string,
	payload []byte,
	extra map[string]dbtypes.AttributeValue,
) dbtypes.TransactWriteItem {
	item := s.buildItem(pk, sk, payload, 1, extra)
	return dbtypes.TransactWriteItem{
		Put: &dbtypes.Put{
			TableName: aws.String(s.tableName),
			Item:      item,
		},
	}
}

func (s *dynamoMapStore) DeleteTx(pk, sk string) dbtypes.TransactWriteItem {
	return dbtypes.TransactWriteItem{
		Delete: &dbtypes.Delete{
			TableName: aws.String(s.tableName),
			Key: map[string]dbtypes.AttributeValue{
				MapAttrPK: avS(pk),
				MapAttrSK: avS(sk),
			},
		},
	}
}

func (s *dynamoMapStore) TransactWrite(ctx context.Context, items []dbtypes.TransactWriteItem) error {
	_, err := s.client.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: items,
	})
	return err
}
