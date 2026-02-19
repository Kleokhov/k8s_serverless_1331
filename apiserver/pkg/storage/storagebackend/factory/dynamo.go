package factory

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"k8s.io/apiserver/pkg/storage/dynamo"
	"k8s.io/apiserver/pkg/storage/etcd3"
	"k8s.io/apiserver/pkg/storage/value/encrypt/identity"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/storagebackend"
)

// newDynamoStorage mirrors the wiring style of newETCD3Storage in etcd3.go
func newDynamoStorage(
	c storagebackend.ConfigForResource,
	newFunc, newListFunc func() runtime.Object,
	resourcePrefix string,
) (storage.Interface, DestroyFunc, error) {

	// print out a test message
	fmt.Println("Initializing DynamoDB storage backend...")
	//
	//return nil, nil, nil

	// Keep parity with etcd3 wiring: if nil, use encrypt-check transformer.
	transformer := c.Transformer
	if transformer == nil {
		transformer = identity.NewEncryptCheckTransformer()
	}

	// ResourceVersion boundary logic (PrepareObjectForStorage, UpdateObject, UpdateList, ...)
	// This is NOT the same thing as runtime.GroupVersioner (EncodeVersioner).
	versioner := storage.APIObjectVersioner{}

	// Reuse the default decoder used by etcd3: decodes bytes and updates RV via storage.Versioner.
	decoder := etcd3.NewDefaultDecoder(c.Codec, versioner)

	ddb, destroyClient, err := newDynamoClient(c)
	if err != nil {
		return nil, nil, err
	}

	bootstrap := true

	s, err := dynamo.New(
		context.Background(),
		ddb,
		c.Dynamo.TableName,
		c.Prefix,
		resourcePrefix,
		c.GroupResource,
		versioner,
		transformer,
		decoder,
		c.Codec,
		bootstrap,
	)
	if err != nil {
		destroyClient()
		return nil, nil, err
	}

	destroy := func() {
		if d, ok := any(s).(interface{ Destroy() }); ok {
			d.Destroy()
		}
		destroyClient()
	}

	return s, destroy, nil
}

func newDynamoClient(c storagebackend.ConfigForResource) (*dynamodb.Client, func(), error) {
	if c.Dynamo.Region == "" {
		return nil, nil, fmt.Errorf("dynamo storage: missing region (c.Dynamo.Region)")
	}

	// If you point at dynamodb-local/localstack, set Endpoint and use dummy static creds
	// to avoid IMDS/timeouts.
	loadOpts := []func(*config.LoadOptions) error{
		config.WithRegion(c.Dynamo.Region),
	}

	if c.Dynamo.Endpoint != "" {
		loadOpts = append(loadOpts,
			config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("dummy", "dummy", "")),
		)
	}

	awsCfg, err := config.LoadDefaultConfig(context.Background(), loadOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("dynamo storage: load aws config: %w", err)
	}

	client := dynamodb.NewFromConfig(awsCfg, func(o *dynamodb.Options) {
		if c.Dynamo.Endpoint != "" {
			o.BaseEndpoint = aws.String(c.Dynamo.Endpoint)
		}

		_ = time.Second
	})

	return client, func() {}, nil
}
