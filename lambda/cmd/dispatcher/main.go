package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	schedulermetrics "k8s.io/kubernetes/pkg/scheduler/metrics"
	"k8s.io/utils/clock"

	controllerawsstore "lambda/pkg/controller/awsstore"
	"lambda/pkg/dispatcher"
	kubeconfigpkg "lambda/pkg/kubeconfig"
	"lambda/pkg/lambdaklog"
	"lambda/pkg/scheduler/backend/awsstore"
	"lambda/pkg/scheduler/backend/queue"
)

const (
	jobQueueMessageGroupID       = "job-controller"
	orphanQueueMessageGroupID    = "job-controller-orphan"
	ttlQueueMessageGroupID       = "ttl-after-finished-controller"
	namespaceQueueMessageGroupID = "namespace-controller"
)

type app struct {
	client              kubernetes.Interface
	cacheStore          *awsstore.CacheStore
	dispatchStore       *awsstore.DispatcherStore
	queue               queue.SchedulingQueue
	controllerQueues    dispatcher.ControllerQueues
	selfTriggerQueue    controllerawsstore.SQSQueue
	selfTriggerInterval time.Duration
}

var appInst *app

func getDuration(name string, def time.Duration) time.Duration {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

func mustEnv(name string) string {
	v := os.Getenv(name)
	if v == "" {
		log.Fatalf("required environment variable %s is not set", name)
	}
	return v
}

func newApp(ctx context.Context) (*app, error) {
	schedulermetrics.Register()

	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}

	kubeCfg, err := kubeconfigpkg.Load()
	if err != nil {
		return nil, err
	}
	client, err := kubernetes.NewForConfig(kubeCfg)
	if err != nil {
		return nil, err
	}

	initialBackoff := getDuration("POD_INITIAL_BACKOFF", queue.DefaultPodInitialBackoffDuration)
	maxBackoff := getDuration("POD_MAX_BACKOFF", queue.DefaultPodMaxBackoffDuration)
	maxUnschedAge := getDuration("POD_MAX_UNSCHEDULABLE_AGE", queue.DefaultPodMaxInUnschedulablePodsDuration)
	backoffTimeFunc := queue.NewBackoffTimeFunc(initialBackoff, maxBackoff)

	schedulingQueue, err := queue.NewSchedulingQueue(
		ctx,
		queue.WithClock(clock.RealClock{}),
		queue.WithAWSConfig(awsCfg),
		queue.WithKubeClient(client),
		queue.WithPodInitialBackoffDuration(initialBackoff),
		queue.WithPodMaxBackoffDuration(maxBackoff),
		queue.WithPodMaxInUnschedulablePodsDuration(maxUnschedAge),
		queue.WithCreateActiveQueue(os.Getenv("ACTIVE_QUEUE_TABLE")),
		queue.WithCreateBackoffQueues(os.Getenv("BACKOFF_QUEUE_TABLE"), backoffTimeFunc),
		queue.WithMiscMapTable(os.Getenv("MISC_MAP_TABLE")),
		queue.WithCreateNominator(),
		queue.WithCreateUnschedulablePods(),
	)
	if err != nil {
		return nil, err
	}

	ddbClient := dynamodb.NewFromConfig(awsCfg)
	cacheMapEnv, err := awsstore.NewDynamoMapEnvFromClient(ctx, ddbClient, os.Getenv("CACHE_MAP_TABLE"))
	if err != nil {
		return nil, err
	}
	cacheStore := awsstore.NewCacheStore(awsstore.NewDynamoMapStore(cacheMapEnv))
	miscMapEnv, err := awsstore.NewDynamoMapEnvFromClient(ctx, ddbClient, os.Getenv("MISC_MAP_TABLE"))
	if err != nil {
		return nil, err
	}
	dispatchStore := awsstore.NewDispatcherStore(awsstore.NewDynamoMapStore(miscMapEnv))

	sqsClient := sqs.NewFromConfig(awsCfg)
	jobQueue, err := controllerawsstore.NewSQSQueue(
		sqsClient,
		mustEnv("JOB_QUEUE_URL"),
		controllerawsstore.WithFIFOMessageGroupID(jobQueueMessageGroupID),
	)
	if err != nil {
		return nil, err
	}
	jobOrphanQueue, err := controllerawsstore.NewSQSQueue(
		sqsClient,
		mustEnv("JOB_ORPHAN_QUEUE_URL"),
		controllerawsstore.WithFIFOMessageGroupID(orphanQueueMessageGroupID),
	)
	if err != nil {
		return nil, err
	}
	ttlQueue, err := controllerawsstore.NewSQSQueue(
		sqsClient,
		mustEnv("TTL_AFTER_FINISHED_QUEUE_URL"),
		controllerawsstore.WithFIFOMessageGroupID(ttlQueueMessageGroupID),
	)
	if err != nil {
		return nil, err
	}
	namespaceQueue, err := controllerawsstore.NewSQSQueue(
		sqsClient,
		mustEnv("NAMESPACE_QUEUE_URL"),
		controllerawsstore.WithFIFOMessageGroupID(namespaceQueueMessageGroupID),
	)
	if err != nil {
		return nil, err
	}

	selfTriggerInterval := getDuration("SELF_TRIGGER_INTERVAL", 10*time.Second)
	var selfTriggerQueue controllerawsstore.SQSQueue
	if selfTriggerURL := os.Getenv("SELF_TRIGGER_QUEUE_URL"); selfTriggerURL != "" {
		selfTriggerQueue, err = controllerawsstore.NewSQSQueue(sqsClient, selfTriggerURL)
		if err != nil {
			return nil, fmt.Errorf("init self-trigger queue: %w", err)
		}
	}

	return &app{
		client:              client,
		cacheStore:          cacheStore,
		dispatchStore:       dispatchStore,
		queue:               schedulingQueue,
		selfTriggerQueue:    selfTriggerQueue,
		selfTriggerInterval: selfTriggerInterval,
		controllerQueues: dispatcher.ControllerQueues{
			Job:       jobQueue,
			JobOrphan: jobOrphanQueue,
			TTL:       ttlQueue,
			Namespace: namespaceQueue,
		},
	}, nil
}

// isSQSTrigger returns true when the Lambda event originated from the SQS
// event-source mapping. Non-SQS invocations (direct invokes, future schedules)
// must not enqueue a self-trigger; doing so would create an additional chain
// on top of the one already running.
func isSQSTrigger(event json.RawMessage) bool {
	var e struct {
		Records []struct{} `json:"Records"`
	}
	return json.Unmarshal(event, &e) == nil && len(e.Records) > 0
}

func handler(ctx context.Context, event json.RawMessage) error {
	start := time.Now()
	defer klog.Flush()

	logger := klog.FromContext(ctx)
	logger.Info("Starting dispatcher lambda invocation")
	_, err := dispatcher.Reconcile(
		ctx,
		logger,
		appInst.client,
		appInst.cacheStore,
		appInst.dispatchStore,
		appInst.queue,
		appInst.controllerQueues,
	)
	if err != nil {
		logger.Error(err, "Dispatcher lambda invocation failed")
	}

	// Only re-enqueue from SQS-triggered invocations. Any other trigger source
	// (direct invoke, a future schedule) must not enqueue or it creates a
	// second chain on top of the running one.
	if appInst.selfTriggerQueue != nil && isSQSTrigger(event) {
		delay := appInst.selfTriggerInterval - time.Since(start)
		if delay < 0 {
			delay = 0
		}
		if sendErr := appInst.selfTriggerQueue.EnqueueAfter(ctx, "tick", delay); sendErr != nil {
			logger.Error(sendErr, "Failed to enqueue self-trigger message")
		}
	}

	// Always return nil so the SQS event-source mapping deletes the consumed
	// message rather than re-enqueuing it.
	return nil
}

func main() {
	lambdaklog.Init()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	var err error
	appInst, err = newApp(ctx)
	if err != nil {
		log.Fatalf("lambda init failed: %v", err)
	}

	lambda.Start(handler)
}
