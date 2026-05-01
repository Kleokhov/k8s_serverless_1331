package scheduler

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	lambdasvc "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	sqssvc "github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	v1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/scheduler/framework"
)

const (
	ServerlessScheduledAtAnnotation = "serverless-scheduler.ctrlless.io/scheduled-at"
	ServerlessBoundAtAnnotation     = "serverless-scheduler.ctrlless.io/bound-at"
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
	ScheduledAt             time.Time  `json:"scheduledAt,omitempty"`
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
		ScheduledAt:             time.Now(),
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

type BinderBatchInvoker interface {
	InvokeBindings(ctx context.Context, reqs []BindingRequest) []error
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

// sqsBinderInvoker enqueues binding requests to an SQS queue so the binder
// Lambda can consume them as a batch via an event source mapping. Compared
// with direct lambda.Invoke, this lets multiple binds amortize per-Lambda
// cold-start and apiserver-client setup, and parallelize across goroutines
// inside a single invocation.
type sqsBinderInvoker struct {
	client   *sqssvc.Client
	queueURL string
}

func NewSQSBinderInvoker(client *sqssvc.Client, queueURL string) BinderInvoker {
	return &sqsBinderInvoker{
		client:   client,
		queueURL: queueURL,
	}
}

func (i *sqsBinderInvoker) InvokeBinding(ctx context.Context, req BindingRequest) error {
	errs := i.InvokeBindings(ctx, []BindingRequest{req})
	if len(errs) == 0 {
		return nil
	}
	return errs[0]
}

func (i *sqsBinderInvoker) InvokeBindings(ctx context.Context, reqs []BindingRequest) []error {
	errs := make([]error, len(reqs))
	if len(reqs) == 0 {
		return errs
	}
	if i == nil || i.client == nil {
		err := fmt.Errorf("binder sqs client is not configured")
		for idx := range errs {
			errs[idx] = err
		}
		return errs
	}
	if i.queueURL == "" {
		err := fmt.Errorf("binder queue URL is not configured")
		for idx := range errs {
			errs[idx] = err
		}
		return errs
	}

	logger := klog.FromContext(ctx)
	logger.Info("Enqueueing binding request batch to binder queue", "binderQueueURL", i.queueURL, "requests", len(reqs))

	const maxSendMessageBatch = 10
	for start := 0; start < len(reqs); start += maxSendMessageBatch {
		end := start + maxSendMessageBatch
		if end > len(reqs) {
			end = len(reqs)
		}

		entries := make([]sqstypes.SendMessageBatchRequestEntry, 0, end-start)
		entryToReq := make(map[string]int, end-start)
		for idx := start; idx < end; idx++ {
			if errs[idx] != nil {
				continue
			}
			payload, err := json.Marshal(reqs[idx])
			if err != nil {
				errs[idx] = fmt.Errorf("marshal binding request: %w", err)
				continue
			}
			id := "binding-" + strconv.Itoa(idx)
			body := string(payload)
			entries = append(entries, sqstypes.SendMessageBatchRequestEntry{
				Id:          &id,
				MessageBody: &body,
			})
			entryToReq[id] = idx
		}
		if len(entries) == 0 {
			continue
		}

		resp, err := i.client.SendMessageBatch(ctx, &sqssvc.SendMessageBatchInput{
			QueueUrl: &i.queueURL,
			Entries:  entries,
		})
		if err != nil {
			for _, entry := range entries {
				if entry.Id == nil {
					continue
				}
				if idx, ok := entryToReq[*entry.Id]; ok {
					errs[idx] = fmt.Errorf("send binding request batch to sqs %q: %w", i.queueURL, err)
				}
			}
			continue
		}

		for _, failed := range resp.Failed {
			if failed.Id == nil {
				continue
			}
			idx, ok := entryToReq[*failed.Id]
			if !ok {
				continue
			}
			code := ""
			if failed.Code != nil {
				code = *failed.Code
			}
			message := ""
			if failed.Message != nil {
				message = *failed.Message
			}
			errs[idx] = fmt.Errorf("send binding request to sqs %q failed: %s %s", i.queueURL, code, message)
		}
	}

	return errs
}

type pendingBindingDispatch struct {
	req     BindingRequest
	fwk     framework.Framework
	podInfo *framework.QueuedPodInfo
	start   time.Time
}

func (sched *Scheduler) dispatchBinding(ctx context.Context, req BindingRequest) error {
	if sched.BinderInvoker == nil {
		klog.FromContext(ctx).Info("Completing binding inline without binder lambda")
		return sched.CompleteBinding(ctx, req)
	}
	return sched.BinderInvoker.InvokeBinding(ctx, req)
}

func (sched *Scheduler) dispatchBindingBatch(ctx context.Context, bindings []pendingBindingDispatch) {
	if len(bindings) == 0 {
		return
	}

	if sched.BinderInvoker == nil {
		for _, binding := range bindings {
			if err := sched.dispatchBinding(ctx, binding.req); err != nil {
				sched.handleBindingDispatchError(ctx, binding.fwk, binding.podInfo, binding.start, err)
			}
		}
		return
	}

	reqs := make([]BindingRequest, len(bindings))
	for idx := range bindings {
		reqs[idx] = bindings[idx].req
	}

	if batcher, ok := sched.BinderInvoker.(BinderBatchInvoker); ok {
		errs := batcher.InvokeBindings(ctx, reqs)
		if len(errs) != len(bindings) {
			err := fmt.Errorf("binder batch returned %d errors for %d bindings", len(errs), len(bindings))
			for _, binding := range bindings {
				sched.handleBindingDispatchError(ctx, binding.fwk, binding.podInfo, binding.start, err)
			}
			return
		}
		for idx, err := range errs {
			if err == nil {
				continue
			}
			binding := bindings[idx]
			sched.handleBindingDispatchError(ctx, binding.fwk, binding.podInfo, binding.start, err)
		}
		return
	}

	for _, binding := range bindings {
		if err := sched.dispatchBinding(ctx, binding.req); err != nil {
			sched.handleBindingDispatchError(ctx, binding.fwk, binding.podInfo, binding.start, err)
		}
	}
}
