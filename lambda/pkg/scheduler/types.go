package scheduler

import (
	"context"

	internalcache "lambda/pkg/scheduler/backend/cache"
	internalqueue "lambda/pkg/scheduler/backend/queue"

	v1 "k8s.io/api/core/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/scheduler/framework"
	"k8s.io/kubernetes/pkg/scheduler/profile"
)

// Scheduler watches for new unscheduled pods. It attempts to find
// nodes that they fit on and writes bindings back to the api server.
type Scheduler struct {
	// It is expected that changes made via Cache will be observed
	// by NodeLister and Algorithm.
	Cache internalcache.Cache

	// NextPod should be a function that blocks until the next pod
	// is available. We don't use a channel for this, because scheduling
	// a pod may take some amount of time and we don't want pods to get
	// stale while they sit in a channel.
	NextPod func(logger klog.Logger) (*framework.QueuedPodInfo, error)

	// FailureHandler is called upon a scheduling failure.
	FailureHandler FailureHandlerFn

	// SchedulePod tries to schedule the given pod to one of the nodes in the node list.
	// Return a struct of ScheduleResult with the name of suggested host on success,
	// otherwise will return a FitError with reasons.
	SchedulePod func(ctx context.Context, fwk framework.Framework, state *framework.CycleState, pod *v1.Pod) (ScheduleResult, error)

	// Close this to shut down the scheduler.
	StopEverything <-chan struct{}

	// SchedulingQueue holds pods to be scheduled
	SchedulingQueue internalqueue.SchedulingQueue

	// Profiles are the scheduling profiles.
	Profiles profile.Map

	// profileFeatures caches extension-point capabilities by scheduler profile name.
	profileFeatures map[string]profileFeatures

	// BinderInvoker hands completed scheduling decisions off to the binder implementation.
	BinderInvoker BinderInvoker

	client clientset.Interface

	percentageOfNodesToScore int32

	nextStartNodeIndex int

	// logger *must* be initialized when creating a Scheduler,
	// otherwise logging functions will access a nil sink and
	// panic.
	logger klog.Logger
}
