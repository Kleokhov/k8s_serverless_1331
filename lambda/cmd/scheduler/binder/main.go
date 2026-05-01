package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/aws/aws-lambda-go/events"
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

// defaultBinderConcurrency caps how many binds run in parallel inside a
// single Lambda invocation. The bind itself is one apiserver PATCH plus a
// few DynamoDB writes; 32 keeps the Go runtime small while saturating the
// apiserver client well past one-at-a-time.
const defaultBinderConcurrency = 32

type app struct {
	scheduler   *schedulerpkg.Scheduler
	concurrency int
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

	return &app{
		scheduler:   sched,
		concurrency: getInt("BINDER_CONCURRENCY", defaultBinderConcurrency),
	}, nil
}

func handler(ctx context.Context, event events.SQSEvent) (events.SQSEventResponse, error) {
	defer klog.Flush()

	logger := klog.FromContext(ctx)
	logger.Info("Starting binder lambda invocation", "records", len(event.Records))

	var (
		resp events.SQSEventResponse
		mu   sync.Mutex
		wg   sync.WaitGroup
	)
	concurrency := appInst.concurrency
	if concurrency <= 0 {
		concurrency = defaultBinderConcurrency
	}
	sem := make(chan struct{}, concurrency)

	failItem := func(messageID, msg string, err error, fields ...interface{}) {
		fields = append(fields, "messageID", messageID)
		logger.Error(err, msg, fields...)
		mu.Lock()
		resp.BatchItemFailures = append(resp.BatchItemFailures,
			events.SQSBatchItemFailure{ItemIdentifier: messageID})
		mu.Unlock()
	}

	for _, rec := range event.Records {
		rec := rec
		var req schedulerpkg.BindingRequest
		if err := json.Unmarshal([]byte(rec.Body), &req); err != nil {
			failItem(rec.MessageId, "Failed to unmarshal binding request", err)
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			fields := []interface{}{
				"suggestedHost", req.SuggestedHost,
				"evaluatedNodes", req.EvaluatedNodes,
				"feasibleNodes", req.FeasibleNodes,
				"attempts", req.Attempts,
			}
			if req.Pod != nil {
				fields = append(fields, "pod", klog.KObj(req.Pod))
			}

			if err := appInst.scheduler.CompleteBinding(ctx, req); err != nil {
				failItem(rec.MessageId, "Bind failed", err, fields...)
				return
			}
			logger.V(2).Info("Bind succeeded", fields...)
		}()
	}
	wg.Wait()

	logger.Info("Completed binder lambda invocation",
		"records", len(event.Records),
		"failed", len(resp.BatchItemFailures))
	return resp, nil
}

func main() {
	lambdaklog.Init()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var err error
	appInst, err = newApp(ctx)
	if err != nil {
		log.Fatalf("lambda init failed: %v", err)
	}

	lambda.Start(handler)
}
