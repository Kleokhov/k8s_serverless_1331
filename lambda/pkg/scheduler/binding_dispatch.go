package scheduler

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	lambdasvc "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	v1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/scheduler/framework"
)

// BindingRequest is the serialized handoff between scheduleOne and the binder Lambda.
type BindingRequest struct {
	Pod                     *v1.Pod    `json:"pod"`
	SuggestedHost           string     `json:"suggestedHost"`
	EvaluatedNodes          int        `json:"evaluatedNodes"`
	FeasibleNodes           int        `json:"feasibleNodes"`
	Attempts                int        `json:"attempts"`
	InitialAttemptTimestamp *time.Time `json:"initialAttemptTimestamp,omitempty"`
	StartTime               time.Time  `json:"startTime"`
}

func newBindingRequest(scheduleResult ScheduleResult, assumedPodInfo *framework.QueuedPodInfo, start time.Time) BindingRequest {
	var initialAttempt *time.Time
	if assumedPodInfo.InitialAttemptTimestamp != nil {
		ts := *assumedPodInfo.InitialAttemptTimestamp
		initialAttempt = &ts
	}

	return BindingRequest{
		Pod:                     assumedPodInfo.Pod.DeepCopy(),
		SuggestedHost:           scheduleResult.SuggestedHost,
		EvaluatedNodes:          scheduleResult.EvaluatedNodes,
		FeasibleNodes:           scheduleResult.FeasibleNodes,
		Attempts:                assumedPodInfo.Attempts,
		InitialAttemptTimestamp: initialAttempt,
		StartTime:               start,
	}
}

func (r BindingRequest) ScheduleResult() ScheduleResult {
	return ScheduleResult{
		SuggestedHost:  r.SuggestedHost,
		EvaluatedNodes: r.EvaluatedNodes,
		FeasibleNodes:  r.FeasibleNodes,
	}
}

func (r BindingRequest) QueuedPodInfo() (*framework.QueuedPodInfo, error) {
	if r.Pod == nil {
		return nil, fmt.Errorf("binding request pod is required")
	}

	podInfo, err := framework.NewPodInfo(r.Pod.DeepCopy())
	if err != nil {
		return nil, err
	}

	var initialAttempt *time.Time
	if r.InitialAttemptTimestamp != nil {
		ts := *r.InitialAttemptTimestamp
		initialAttempt = &ts
	}

	return &framework.QueuedPodInfo{
		PodInfo:                 podInfo,
		Timestamp:               r.StartTime,
		Attempts:                r.Attempts,
		InitialAttemptTimestamp: initialAttempt,
	}, nil
}

type BinderInvoker interface {
	InvokeBinding(ctx context.Context, req BindingRequest) error
}

type lambdaBinderInvoker struct {
	client       *lambdasvc.Client
	functionName string
}

func NewLambdaBinderInvoker(client *lambdasvc.Client, functionName string) BinderInvoker {
	return &lambdaBinderInvoker{
		client:       client,
		functionName: functionName,
	}
}

func (i *lambdaBinderInvoker) InvokeBinding(ctx context.Context, req BindingRequest) error {
	if i == nil || i.client == nil {
		return fmt.Errorf("binder lambda client is not configured")
	}
	if i.functionName == "" {
		return fmt.Errorf("binder lambda function name is not configured")
	}

	payload, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal binding request: %w", err)
	}

	fields := []interface{}{
		"binderFunction", i.functionName,
		"suggestedHost", req.SuggestedHost,
		"evaluatedNodes", req.EvaluatedNodes,
		"feasibleNodes", req.FeasibleNodes,
		"attempts", req.Attempts,
	}
	if req.Pod != nil {
		fields = append(fields, "pod", klog.KObj(req.Pod))
	}
	klog.FromContext(ctx).Info("Dispatching binding request to binder lambda", fields...)

	resp, err := i.client.Invoke(ctx, &lambdasvc.InvokeInput{
		FunctionName:   &i.functionName,
		InvocationType: lambdatypes.InvocationTypeEvent,
		Payload:        payload,
	})
	if err != nil {
		return fmt.Errorf("invoke binder lambda %q: %w", i.functionName, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("invoke binder lambda %q returned status code %d", i.functionName, resp.StatusCode)
	}

	return nil
}

func (sched *Scheduler) dispatchBinding(ctx context.Context, req BindingRequest) error {
	if sched.BinderInvoker == nil {
		klog.FromContext(ctx).Info("Completing binding inline without binder lambda")
		return sched.CompleteBinding(ctx, req)
	}
	return sched.BinderInvoker.InvokeBinding(ctx, req)
}
