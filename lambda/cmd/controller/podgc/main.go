package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	lambdaruntime "github.com/aws/aws-lambda-go/lambda"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	podgcpkg "lambda/pkg/controller/podgc"
	kubeconfigpkg "lambda/pkg/kubeconfig"
	"lambda/pkg/lambdaklog"
)

const (
	defaultRunOnceIterations = 5
)

type app struct {
	controller        *podgcpkg.PodGCController
	runOnceIterations int
}

var appInst *app

func getInt(name string, def int) int {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func getPositiveInt(name string, def int) int {
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
	kubeCfg, err := kubeconfigpkg.Load()
	if err != nil {
		return nil, fmt.Errorf("load kube client config: %w", err)
	}

	client, err := kubernetes.NewForConfig(kubeCfg)
	if err != nil {
		return nil, fmt.Errorf("create kube client: %w", err)
	}

	controller, err := podgcpkg.NewPodGC(
		client,
		getInt("PODGC_TERMINATED_THRESHOLD", podgcpkg.DefaultTerminatedPodThreshold),
	)
	if err != nil {
		return nil, fmt.Errorf("create podgc controller: %w", err)
	}

	return &app{
		controller:        controller,
		runOnceIterations: getPositiveInt("PODGC_RUN_ONCE_ITERATIONS", defaultRunOnceIterations),
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

func handler(ctx context.Context) (podgcpkg.Result, error) {
	defer klog.Flush()

	logger := klog.FromContext(ctx)
	logger.Info("Starting PodGC lambda invocation", "iterations", appInst.runOnceIterations)

	var result podgcpkg.Result
	var errs []error
	for i := 0; i < appInst.runOnceIterations; i++ {
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			break
		}
		runResult, err := appInst.controller.RunOnce(ctx)
		addPodGCResults(&result, runResult)
		if err != nil {
			errs = append(errs, fmt.Errorf("runOnce iteration %d: %w", i+1, err))
		}
	}
	return result, errors.Join(errs...)
}

func addPodGCResults(total *podgcpkg.Result, current podgcpkg.Result) {
	total.PodsListed += current.PodsListed
	total.NodesListed += current.NodesListed
	total.TerminatedDeleted += current.TerminatedDeleted
	total.TerminatingDeleted += current.TerminatingDeleted
	total.OrphanedDeleted += current.OrphanedDeleted
	total.UnscheduledDeleted += current.UnscheduledDeleted
}

func main() {
	lambdaruntime.Start(handler)
}
