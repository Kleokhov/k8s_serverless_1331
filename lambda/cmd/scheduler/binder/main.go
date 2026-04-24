package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
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
	scheduler *schedulerpkg.Scheduler
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
	cacheMapStore := awsstore.NewDynamoMapStore(cacheMapEnv)

	sched, err := schedulerpkg.New(
		ctx,
		client,
		schedulerpkg.WithKubeConfig(kubeCfg),
		schedulerpkg.WithSchedulingQueue(schedulingQueue),
		schedulerpkg.WithCacheMapStore(cacheMapStore),
	)
	if err != nil {
		return nil, err
	}

	return &app{scheduler: sched}, nil
}

func handler(ctx context.Context, req schedulerpkg.BindingRequest) (response, error) {
	defer klog.Flush()

	logger := klog.FromContext(ctx)
	fields := []interface{}{
		"suggestedHost", req.SuggestedHost,
		"evaluatedNodes", req.EvaluatedNodes,
		"feasibleNodes", req.FeasibleNodes,
		"attempts", req.Attempts,
	}
	if req.Pod != nil {
		fields = append(fields, "pod", klog.KObj(req.Pod))
	}
	logger.Info("Starting binder lambda invocation", fields...)

	if err := appInst.scheduler.CompleteBinding(ctx, req); err != nil {
		logger.Error(err, "Binder lambda invocation failed", fields...)
		return response{}, err
	}
	return response{Processed: true}, nil
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
