package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/events"
	lambdaruntime "github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"
	"k8s.io/klog/v2"

	"lambda/pkg/controller/awsstore"
	namespacepkg "lambda/pkg/controller/namespace"
	kubeconfigpkg "lambda/pkg/kubeconfig"
	"lambda/pkg/lambdaklog"
)

const (
	namespaceQueueMessageGroupID = "namespace-controller"
)

type app struct {
	controller *namespacepkg.NamespaceController
}

var appInst *app

func mustEnv(name string) string {
	v := os.Getenv(name)
	if v == "" {
		log.Fatalf("required environment variable %s is not set", name)
	}
	return v
}

func newApp(ctx context.Context) (*app, error) {
	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}

	kubeCfg, err := kubeconfigpkg.Load()
	if err != nil {
		return nil, fmt.Errorf("load kube client config: %w", err)
	}

	client, err := kubernetes.NewForConfig(kubeCfg)
	if err != nil {
		return nil, fmt.Errorf("create kube client: %w", err)
	}

	metadataClient, err := metadata.NewForConfig(kubeCfg)
	if err != nil {
		return nil, fmt.Errorf("create metadata client: %w", err)
	}

	queue, err := awsstore.NewSQSQueue(
		sqs.NewFromConfig(awsCfg),
		mustEnv("NAMESPACE_QUEUE_URL"),
		awsstore.WithFIFOMessageGroupID(namespaceQueueMessageGroupID),
	)
	if err != nil {
		return nil, fmt.Errorf("create namespace queue: %w", err)
	}

	controller, err := namespacepkg.NewLambdaController(ctx, queue, client, metadataClient)
	if err != nil {
		return nil, fmt.Errorf("create namespace controller: %w", err)
	}

	return &app{controller: controller}, nil
}

func init() {
	lambdaklog.Init()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var err error
	appInst, err = newApp(ctx)
	if err != nil {
		log.Fatalf("lambda init failed: %v", err)
	}
}

func handler(ctx context.Context, event events.SQSEvent) (events.SQSEventResponse, error) {
	defer klog.Flush()

	logger := klog.FromContext(ctx)
	logger.Info("Starting namespace controller lambda invocation", "records", len(event.Records))

	items := make([]awsstore.QueuedItem, 0, len(event.Records))
	for _, r := range event.Records {
		items = append(items, awsstore.QueuedItem{
			MessageID:     r.MessageId,
			Body:          r.Body,
			ReceiptHandle: r.ReceiptHandle,
		})
	}

	_, failedIDs := appInst.controller.ProcessItems(ctx, items)

	var response events.SQSEventResponse
	for _, id := range failedIDs {
		response.BatchItemFailures = append(response.BatchItemFailures, events.SQSBatchItemFailure{
			ItemIdentifier: id,
		})
	}
	return response, nil
}

func main() {
	lambdaruntime.Start(handler)
}
