package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	lambdaruntime "github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	schedulermetrics "k8s.io/kubernetes/pkg/scheduler/metrics"
	"k8s.io/utils/clock"

	kubeconfigpkg "lambda/pkg/kubeconfig"
	"lambda/pkg/lambdaklog"
	schedulerpkg "lambda/pkg/scheduler"
	"lambda/pkg/scheduler/backend/awsstore"
	"lambda/pkg/scheduler/backend/queue"
)

type response struct {
	Processed bool `json:"processed"`
}

type app struct {
	scheduler            *schedulerpkg.Scheduler
	maxPodsPerInvocation int
}

// Global singleton for this execution environment.
// Created once during Lambda init, reused on warm invocations.
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

func getInt(name string, def int) int {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

func newApp(ctx context.Context) (*app, error) {
	schedulermetrics.Register()

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
		return nil, fmt.Errorf("create scheduling queue: %w", err)
	}

	ddbClient := dynamodb.NewFromConfig(awsCfg)

	cacheMapEnv, err := awsstore.NewDynamoMapEnvFromClient(ctx, ddbClient, os.Getenv("CACHE_MAP_TABLE"))
	if err != nil {
		return nil, fmt.Errorf("create dynamo map env: %w", err)
	}

	cacheMapStore := awsstore.NewDynamoMapStore(cacheMapEnv)

	binderQueueURL := os.Getenv("BINDER_QUEUE_URL")
	if binderQueueURL == "" {
		return nil, fmt.Errorf("BINDER_QUEUE_URL is not set")
	}

	binderInvoker := schedulerpkg.NewSQSBinderInvoker(
		sqs.NewFromConfig(awsCfg),
		binderQueueURL,
	)

	sched, err := schedulerpkg.New(
		ctx,
		client,
		schedulerpkg.WithKubeConfig(kubeCfg),
		schedulerpkg.WithSchedulingQueue(schedulingQueue),
		schedulerpkg.WithCacheMapStore(cacheMapStore),
		schedulerpkg.WithBinderInvoker(binderInvoker),
	)
	if err != nil {
		return nil, fmt.Errorf("create scheduler: %w", err)
	}

	return &app{
		scheduler:            sched,
		maxPodsPerInvocation: getInt("SCHEDULE_ONE_MAX_PODS", 25),
	}, nil
}

func init() {
	lambdaklog.Init()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var err error
	appInst, err = newApp(ctx)
	if err != nil {
		// Fail the execution environment during init.
		// Lambda will treat this as an initialization failure.
		log.Fatalf("lambda init failed: %v", err)
	}
}

func handler(ctx context.Context) (response, error) {
	defer klog.Flush()

	logger := klog.FromContext(ctx)
	maxPods := appInst.maxPodsPerInvocation
	logger.Info("Starting ScheduleOne lambda invocation", "maxPods", maxPods)
	processed := appInst.scheduler.ScheduleUpTo(ctx, maxPods)
	logger.Info("Completed ScheduleOne lambda invocation", "processedPods", processed, "maxPods", maxPods)
	return response{Processed: true}, nil
}

func main() {
	lambdaruntime.Start(handler)
}
