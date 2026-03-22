package dynamo

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// EnsureTableBootstrap makes sure the table exists and the meta row exists.
func EnsureTableBootstrap(ctx context.Context, ddb *dynamodb.Client, tableName string) error {
	if err := EnsureResourceTable(ctx, ddb, tableName); err != nil {
		return err
	}
	if err := ensureMetaRow(ctx, ddb, tableName); err != nil {
		return err
	}
	return nil
}

// EnsureResourceTable creates the per-resource table if it does not exist.
func EnsureResourceTable(ctx context.Context, ddb *dynamodb.Client, tableName string) error {
	_, err := ddb.DescribeTable(ctx, &dynamodb.DescribeTableInput{
		TableName: aws.String(tableName),
	})
	if err != nil {
		var rnfe *ddbtypes.ResourceNotFoundException
		if !errors.As(err, &rnfe) {
			return fmt.Errorf("DescribeTable(%s): %w", tableName, err)
		}

		_, err = ddb.CreateTable(ctx, &dynamodb.CreateTableInput{
			TableName:   aws.String(tableName),
			BillingMode: ddbtypes.BillingModePayPerRequest,
			AttributeDefinitions: []ddbtypes.AttributeDefinition{
				{AttributeName: aws.String(attrPK), AttributeType: ddbtypes.ScalarAttributeTypeS},
				{AttributeName: aws.String(attrSK), AttributeType: ddbtypes.ScalarAttributeTypeS},
			},
			KeySchema: []ddbtypes.KeySchemaElement{
				{AttributeName: aws.String(attrPK), KeyType: ddbtypes.KeyTypeHash},
				{AttributeName: aws.String(attrSK), KeyType: ddbtypes.KeyTypeRange},
			},
		})
		if err != nil {
			return fmt.Errorf("CreateTable(%s): %w", tableName, err)
		}

		waiter := dynamodb.NewTableExistsWaiter(ddb)
		waitCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()

		if err := waiter.Wait(
			waitCtx,
			&dynamodb.DescribeTableInput{TableName: aws.String(tableName)},
			60*time.Second,
		); err != nil {
			return fmt.Errorf("wait for table %s to exist: %w", tableName, err)
		}
	}

	// Best-effort TTL enablement for both newly created and already-existing tables.
	_, _ = ddb.UpdateTimeToLive(ctx, &dynamodb.UpdateTimeToLiveInput{
		TableName: aws.String(tableName),
		TimeToLiveSpecification: &ddbtypes.TimeToLiveSpecification{
			AttributeName: aws.String(ttlAttribute),
			Enabled:       aws.Bool(true),
		},
	})

	return nil
}

// ensureMetaRow creates the meta row if it doesn't exist.
func ensureMetaRow(ctx context.Context, ddb *dynamodb.Client, tableName string) error {
	// Create meta row if it doesn't exist.
	_, err := ddb.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(tableName),
		Item: map[string]ddbtypes.AttributeValue{
			attrPK:        &ddbtypes.AttributeValueMemberS{Value: metaPK},
			attrSK:        &ddbtypes.AttributeValueMemberS{Value: metaSK},
			attrCurrentRV: &ddbtypes.AttributeValueMemberN{Value: strconv.FormatUint(minInitialRV, 10)},
		},
		ConditionExpression: aws.String("attribute_not_exists(#pk)"),
		ExpressionAttributeNames: map[string]string{
			"#pk": attrPK,
		},
	})
	if err == nil {
		return nil
	}
	var cfe *ddbtypes.ConditionalCheckFailedException
	if errors.As(err, &cfe) {
		// already exists
		return nil
	}
	return fmt.Errorf("PutItem(meta row) table=%s: %w", tableName, err)
}
