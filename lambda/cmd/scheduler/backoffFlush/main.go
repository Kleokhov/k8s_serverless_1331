package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"k8s.io/klog/v2"
	schedulermetrics "k8s.io/kubernetes/pkg/scheduler/metrics"
	"k8s.io/utils/clock"

	"lambda/pkg/lambdaklog"
	"lambda/pkg/scheduler/backend/queue"
)

type response struct {
	Activated int `json:"activated"`
}

type app struct {
	queue *queue.PriorityQueue
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

	initialBackoff := getDuration("POD_INITIAL_BACKOFF", queue.DefaultPodInitialBackoffDuration)
	maxBackoff := getDuration("POD_MAX_BACKOFF", queue.DefaultPodMaxBackoffDuration)
	backoffTimeFunc := queue.NewBackoffTimeFunc(initialBackoff, maxBackoff)

	pq, err := queue.NewBackoffFlushQueue(
		ctx,
		queue.WithClock(clock.RealClock{}),
		queue.WithAWSConfig(awsCfg),
		queue.WithPodInitialBackoffDuration(initialBackoff),
		queue.WithPodMaxBackoffDuration(maxBackoff),
		queue.WithCreateActiveQueue(os.Getenv("ACTIVE_QUEUE_TABLE")),
		queue.WithCreateBackoffQueues(os.Getenv("BACKOFF_QUEUE_TABLE"), backoffTimeFunc),
	)
	if err != nil {
		return nil, err
	}

	return &app{queue: pq}, nil
}

func handler(ctx context.Context) (response, error) {
	defer klog.Flush()

	logger := klog.FromContext(ctx)
	logger.Info("Starting backoff flush lambda invocation")
	activated := appInst.queue.FlushBackoffQCompletedOnce(logger)
	logger.Info("Completed backoff flush lambda invocation", "activated", activated)
	return response{Activated: activated}, nil
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
