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
	"k8s.io/klog/v2"

	"lambda/pkg/controller/awsstore"
	jobpkg "lambda/pkg/controller/job"
	kubeconfigpkg "lambda/pkg/kubeconfig"
	"lambda/pkg/lambdaklog"
)

const (
	jobQueueMessageGroupID    = "job-controller"
	orphanQueueMessageGroupID = "job-controller-orphan"
)

type app struct {
	controller  *jobpkg.Controller
	jobQueueARN string
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

	jobQueue, err := awsstore.NewSQSQueue(
		sqs.NewFromConfig(awsCfg),
		mustEnv("JOB_QUEUE_URL"),
		awsstore.WithFIFOMessageGroupID(jobQueueMessageGroupID),
	)
	if err != nil {
		return nil, fmt.Errorf("create job queue: %w", err)
	}

	orphanQueue, err := awsstore.NewSQSQueue(
		sqs.NewFromConfig(awsCfg),
		mustEnv("JOB_ORPHAN_QUEUE_URL"),
		awsstore.WithFIFOMessageGroupID(orphanQueueMessageGroupID),
	)
	if err != nil {
		return nil, fmt.Errorf("create orphan queue: %w", err)
	}

	controller, err := jobpkg.NewLambdaController(
		jobQueue,
		orphanQueue,
		client,
	)
	if err != nil {
		return nil, fmt.Errorf("create job controller: %w", err)
	}

	return &app{
		controller:  controller,
		jobQueueARN: mustEnv("JOB_QUEUE_ARN"),
	}, nil
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
	logger.Info("Starting Job controller lambda invocation", "records", len(event.Records))

	var jobItems, orphanItems []awsstore.QueuedItem
	for _, r := range event.Records {
		item := awsstore.QueuedItem{
			MessageID:     r.MessageId,
			Body:          r.Body,
			ReceiptHandle: r.ReceiptHandle,
		}
		if r.EventSourceARN == appInst.jobQueueARN {
			jobItems = append(jobItems, item)
		} else {
			orphanItems = append(orphanItems, item)
		}
	}

	var failedIDs []string
	if len(jobItems) > 0 {
		_, ids := appInst.controller.ProcessJobItems(ctx, jobItems)
		failedIDs = append(failedIDs, ids...)
	}
	if len(orphanItems) > 0 {
		_, ids := appInst.controller.ProcessOrphanItems(ctx, orphanItems)
		failedIDs = append(failedIDs, ids...)
	}

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
