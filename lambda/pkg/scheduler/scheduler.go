/*
Copyright 2014 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package scheduler

import (
	"context"
	"errors"
	"fmt"
	"time"

	"lambda/pkg/scheduler/backend/awsstore"
	internalcache "lambda/pkg/scheduler/backend/cache"
	internalqueue "lambda/pkg/scheduler/backend/queue"

	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
	clientsetscheme "k8s.io/client-go/kubernetes/scheme"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/events"
	"k8s.io/klog/v2"
	configv1 "k8s.io/kube-scheduler/config/v1"
	schedulerapi "k8s.io/kubernetes/pkg/scheduler/apis/config"
	"k8s.io/kubernetes/pkg/scheduler/apis/config/scheme"
	"k8s.io/kubernetes/pkg/scheduler/framework"
	"k8s.io/kubernetes/pkg/scheduler/framework/parallelize"
	frameworkplugins "k8s.io/kubernetes/pkg/scheduler/framework/plugins"
	frameworkruntime "k8s.io/kubernetes/pkg/scheduler/framework/runtime"
	"k8s.io/kubernetes/pkg/scheduler/metrics"
	"k8s.io/kubernetes/pkg/scheduler/profile"
	"k8s.io/utils/clock"
)

// ErrNoNodesAvailable is used to describe the error that no nodes available to schedule pods.
var ErrNoNodesAvailable = fmt.Errorf("no nodes available to schedule pods")

func (sched *Scheduler) applyDefaultHandlers() {
	sched.SchedulePod = sched.schedulePod
	sched.FailureHandler = sched.handleSchedulingFailure
}

type schedulerOptions struct {
	clock                  clock.WithTicker
	componentConfigVersion string
	kubeConfig             *restclient.Config
	// Overridden by profile level percentageOfNodesToScore if set in v1.
	percentageOfNodesToScore          int32
	podInitialBackoffSeconds          int64
	podMaxBackoffSeconds              int64
	podMaxInUnschedulablePodsDuration time.Duration
	// Contains out-of-tree plugins to be merged with the in-tree registry.
	frameworkOutOfTreeRegistry frameworkruntime.Registry
	profiles                   []schedulerapi.KubeSchedulerProfile
	parallelism                int32
	applyDefaultProfile        bool
	cacheMapStore              awsstore.DynamoMap
	schedulingQueue            internalqueue.SchedulingQueue
	binderInvoker              BinderInvoker
}

// Option configures a Scheduler
type Option func(*schedulerOptions)

// ScheduleResult represents the result of scheduling a pod.
type ScheduleResult struct {
	// Name of the selected node.
	SuggestedHost string
	// The number of nodes the scheduler evaluated the pod against in the filtering
	// phase and beyond.
	EvaluatedNodes int
	// The number of nodes out of the evaluated ones that fit the pod.
	FeasibleNodes int
	// The nominating info for scheduling cycle.
	nominatingInfo *framework.NominatingInfo
}

// WithComponentConfigVersion sets the component config version to the
// KubeSchedulerConfiguration version used. The string should be the full
// scheme group/version of the external type we converted from (for example
// "kubescheduler.config.k8s.io/v1")
func WithComponentConfigVersion(apiVersion string) Option {
	return func(o *schedulerOptions) {
		o.componentConfigVersion = apiVersion
	}
}

// WithKubeConfig sets the kube config for Scheduler.
func WithKubeConfig(cfg *restclient.Config) Option {
	return func(o *schedulerOptions) {
		o.kubeConfig = cfg
	}
}

// WithProfiles sets profiles for Scheduler. By default, there is one profile
// with the name "default-scheduler".
func WithProfiles(p ...schedulerapi.KubeSchedulerProfile) Option {
	return func(o *schedulerOptions) {
		o.profiles = p
		o.applyDefaultProfile = false
	}
}

// WithParallelism sets the parallelism for all scheduler algorithms. Default is 16.
func WithParallelism(threads int32) Option {
	return func(o *schedulerOptions) {
		o.parallelism = threads
	}
}

// WithPercentageOfNodesToScore sets percentageOfNodesToScore for Scheduler.
// The default value of 0 will use an adaptive percentage: 50 - (num of nodes)/125.
func WithPercentageOfNodesToScore(percentageOfNodesToScore *int32) Option {
	return func(o *schedulerOptions) {
		if percentageOfNodesToScore != nil {
			o.percentageOfNodesToScore = *percentageOfNodesToScore
		}
	}
}

// WithFrameworkOutOfTreeRegistry sets the registry for out-of-tree plugins. Those plugins
// will be appended to the default registry.
func WithFrameworkOutOfTreeRegistry(registry frameworkruntime.Registry) Option {
	return func(o *schedulerOptions) {
		o.frameworkOutOfTreeRegistry = registry
	}
}

// WithPodInitialBackoffSeconds sets podInitialBackoffSeconds for Scheduler, the default value is 1
func WithPodInitialBackoffSeconds(podInitialBackoffSeconds int64) Option {
	return func(o *schedulerOptions) {
		o.podInitialBackoffSeconds = podInitialBackoffSeconds
	}
}

// WithPodMaxBackoffSeconds sets podMaxBackoffSeconds for Scheduler, the default value is 10
func WithPodMaxBackoffSeconds(podMaxBackoffSeconds int64) Option {
	return func(o *schedulerOptions) {
		o.podMaxBackoffSeconds = podMaxBackoffSeconds
	}
}

// WithPodMaxInUnschedulablePodsDuration sets podMaxInUnschedulablePodsDuration for PriorityQueue.
func WithPodMaxInUnschedulablePodsDuration(duration time.Duration) Option {
	return func(o *schedulerOptions) {
		o.podMaxInUnschedulablePodsDuration = duration
	}
}

// WithClock sets clock for PriorityQueue, the default clock is clock.RealClock.
func WithClock(clock clock.WithTicker) Option {
	return func(o *schedulerOptions) {
		o.clock = clock
	}
}

// WithCacheMapStore sets the Dynamo-backed map store used by the scheduler cache.
func WithCacheMapStore(mapStore awsstore.DynamoMap) Option {
	return func(o *schedulerOptions) {
		o.cacheMapStore = mapStore
	}
}

// WithSchedulingQueue sets the queue implementation used by the scheduler.
func WithSchedulingQueue(q internalqueue.SchedulingQueue) Option {
	return func(o *schedulerOptions) {
		o.schedulingQueue = q
	}
}

// WithBinderInvoker sets the binding handoff implementation used after scheduling succeeds.
func WithBinderInvoker(invoker BinderInvoker) Option {
	return func(o *schedulerOptions) {
		o.binderInvoker = invoker
	}
}

var defaultSchedulerOptions = schedulerOptions{
	clock:                             clock.RealClock{},
	percentageOfNodesToScore:          schedulerapi.DefaultPercentageOfNodesToScore,
	podInitialBackoffSeconds:          int64(internalqueue.DefaultPodInitialBackoffDuration.Seconds()),
	podMaxBackoffSeconds:              int64(internalqueue.DefaultPodMaxBackoffDuration.Seconds()),
	podMaxInUnschedulablePodsDuration: internalqueue.DefaultPodMaxInUnschedulablePodsDuration,
	parallelism:                       int32(parallelize.DefaultParallelism),
	// Ideally we would statically set the default profile here, but we can't because
	// creating the default profile may require testing feature gates, which may get
	// set dynamically in tests. Therefore, we delay creating it until New is actually
	// invoked.
	applyDefaultProfile: true,
}

// New returns a Scheduler
func New(ctx context.Context, client clientset.Interface, opts ...Option) (*Scheduler, error) {
	logger := klog.FromContext(ctx)
	stopEverything := ctx.Done()

	eventBroadcaster := events.NewBroadcaster(&events.EventSinkImpl{Interface: client.EventsV1()})
	recorderFactory := func(name string) events.EventRecorder {
		return eventBroadcaster.NewRecorder(clientsetscheme.Scheme, name)
	}

	options := defaultSchedulerOptions
	for _, opt := range opts {
		opt(&options)
	}

	if options.applyDefaultProfile {
		var versionedCfg configv1.KubeSchedulerConfiguration
		scheme.Scheme.Default(&versionedCfg)
		cfg := schedulerapi.KubeSchedulerConfiguration{}
		if err := scheme.Scheme.Convert(&versionedCfg, &cfg, nil); err != nil {
			return nil, err
		}
		options.profiles = cfg.Profiles
	}

	registry := frameworkplugins.NewInTreeRegistry()
	if err := registry.Merge(options.frameworkOutOfTreeRegistry); err != nil {
		return nil, err
	}

	metrics.Register()

	profiles, err := profile.NewMap(ctx, options.profiles, registry, recorderFactory,
		frameworkruntime.WithComponentConfigVersion(options.componentConfigVersion),
		frameworkruntime.WithClientSet(client),
		frameworkruntime.WithKubeConfig(options.kubeConfig),
		frameworkruntime.WithParallelism(int(options.parallelism)),
	)
	if err != nil {
		return nil, fmt.Errorf("initializing profiles: %v", err)
	}

	if len(profiles) == 0 {
		return nil, errors.New("at least one profile is required")
	}

	podQueue := options.schedulingQueue
	if podQueue == nil {
		podQueue, err = internalqueue.NewSchedulingQueue(
			ctx,
			internalqueue.WithClock(options.clock),
			internalqueue.WithPodInitialBackoffDuration(time.Duration(options.podInitialBackoffSeconds)*time.Second),
			internalqueue.WithPodMaxBackoffDuration(time.Duration(options.podMaxBackoffSeconds)*time.Second),
			internalqueue.WithPodMaxInUnschedulablePodsDuration(options.podMaxInUnschedulablePodsDuration),
		)
		if err != nil {
			return nil, fmt.Errorf("initializing scheduling queue: %v", err)
		}
	}
	if options.cacheMapStore == nil {
		return nil, errors.New("cache map store is not configured")
	}

	for _, fwk := range profiles {
		fwk.SetPodNominator(podQueue)
		fwk.SetPodActivator(podQueue)
	}

	profileFeatures := make(map[string]profileFeatures, len(profiles))
	for name, fwk := range profiles {
		profileFeatures[name] = buildProfileFeatures(fwk)
	}

	schedulerCache := internalcache.New(ctx, options.cacheMapStore)

	sched := &Scheduler{
		Cache:                    schedulerCache,
		client:                   client,
		percentageOfNodesToScore: options.percentageOfNodesToScore,
		StopEverything:           stopEverything,
		SchedulingQueue:          podQueue,
		Profiles:                 profiles,
		profileFeatures:          profileFeatures,
		BinderInvoker:            options.binderInvoker,
		logger:                   logger,
	}
	sched.NextPod = podQueue.Pop
	sched.applyDefaultHandlers()

	return sched, nil
}

// Run begins watching and scheduling. It starts scheduling and blocked until the context is done.
func (sched *Scheduler) Run(ctx context.Context) {
	logger := klog.FromContext(ctx)
	sched.SchedulingQueue.Run(logger)

	// We need to start scheduleOne loop in a dedicated goroutine,
	// because scheduleOne function hangs on getting the next item
	// from the SchedulingQueue.
	// If there are no new pods to schedule, it will be hanging there
	// and if done in this goroutine it will be blocking closing
	// SchedulingQueue, in effect causing a deadlock on shutdown.
	go wait.UntilWithContext(ctx, sched.ScheduleOne, 0)

	<-ctx.Done()
	sched.SchedulingQueue.Close()

	// If the plugins satisfy the io.Closer interface, they are closed.
	err := sched.Profiles.Close()
	if err != nil {
		logger.Error(err, "Failed to close plugins")
	}
}

type FailureHandlerFn func(ctx context.Context, fwk framework.Framework, podInfo *framework.QueuedPodInfo, status *framework.Status, nominatingInfo *framework.NominatingInfo, start time.Time)
