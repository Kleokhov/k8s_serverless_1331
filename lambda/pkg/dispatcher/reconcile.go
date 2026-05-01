package dispatcher

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/sync/errgroup"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	corev1helpers "k8s.io/component-helpers/scheduling/corev1"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/scheduler/framework"

	"lambda/pkg/scheduler/backend/awsstore"
	"lambda/pkg/scheduler/backend/queue"
)

type Result struct {
	NodesAdded         int `json:"nodesAdded"`
	NodesUpdated       int `json:"nodesUpdated"`
	NodesDeleted       int `json:"nodesDeleted"`
	PodsAdded          int `json:"podsAdded"`    // scheduled pods added to cache
	PodsUpdated        int `json:"podsUpdated"`  // scheduled pods updated in cache
	PodsDeleted        int `json:"podsDeleted"`  // scheduled pods removed from cache
	PodsEnqueued       int `json:"podsEnqueued"` // unscheduled pods added/updated in queue
	JobSyncsEnqueued   int `json:"jobSyncsEnqueued"`
	JobOrphansEnqueued int `json:"jobOrphansEnqueued"`
	TTLJobsEnqueued    int `json:"ttlJobsEnqueued"`
	NamespacesEnqueued int `json:"namespacesEnqueued"`
}

type clusterState struct {
	k8sNodes           *corev1.NodeList
	allPods            *corev1.PodList
	allJobs            *batchv1.JobList
	allNamespaces      *corev1.NamespaceList
	dbNodes            map[string]*awsstore.NodeRecord
	dbPodStates        map[string]*awsstore.PodStateRecord
	dispatchJobs       map[string]*awsstore.DispatchJobState
	dispatchPods       map[string]*awsstore.DispatchPodState
	dispatchNamespaces map[string]*awsstore.DispatchNamespaceState
	assumedKeys        []string
	pendingPods        []*corev1.Pod
	pendingSummary     string
}

type reconcileRun struct {
	logger           klog.Logger
	cacheStore       *awsstore.CacheStore
	dispatchStore    *awsstore.DispatcherStore
	schedulingQueue  queue.SchedulingQueue
	controllerQueues ControllerQueues
	state            clusterState
	now              time.Time
	res              Result

	k8sNodeMap      map[string]*corev1.Node
	allPodsByKey    map[string]*corev1.Pod
	jobs            map[string]*batchv1.Job
	jobMatchers     map[string][]compiledJobSelector
	namespaces      map[string]*corev1.Namespace
	assumed         map[string]struct{}
	scheduledPods   map[string]*corev1.Pod
	unscheduledPods map[string]*corev1.Pod
	pendingMap      map[string]*corev1.Pod

	dirtyNodes              map[string]*awsstore.NodeRecord
	deletedNodes            map[string]struct{}
	dirtyPodStates          map[string]*awsstore.PodStateRecord
	deletedPodStates        map[string]struct{}
	deletedAssumedKeys      map[string]struct{}
	nodePodDeltas           map[string]*nodePodDelta
	nodePodOps              map[string]*nodePodPersistOps
	dirtyDispatchJobs       map[string]*awsstore.DispatchJobState
	deletedDispatchJobs     map[string]struct{}
	dirtyDispatchPods       map[string]*awsstore.DispatchPodState
	deletedDispatchPods     map[string]struct{}
	dirtyDispatchNamespaces map[string]*awsstore.DispatchNamespaceState
	deletedDispatchNS       map[string]struct{}
}

func fetchAll(
	ctx context.Context,
	client kubernetes.Interface,
	cacheStore *awsstore.CacheStore,
	dispatchStore *awsstore.DispatcherStore,
	q queue.SchedulingQueue,
) (clusterState, error) {
	var s clusterState

	g, gCtx := errgroup.WithContext(ctx)

	g.Go(func() (err error) {
		s.k8sNodes, err = client.CoreV1().Nodes().List(gCtx, metav1.ListOptions{
			ResourceVersion: "0",
		})
		if err != nil {
			return fmt.Errorf("list nodes from API: %w", err)
		}
		return nil
	})

	g.Go(func() (err error) {
		s.allPods, err = client.CoreV1().Pods("").List(gCtx, metav1.ListOptions{
			ResourceVersion: "0",
		})
		if err != nil {
			return fmt.Errorf("list pods from API: %w", err)
		}
		return nil
	})

	g.Go(func() (err error) {
		s.allJobs, err = client.BatchV1().Jobs("").List(gCtx, metav1.ListOptions{
			ResourceVersion: "0",
		})
		if err != nil {
			return fmt.Errorf("list jobs from API: %w", err)
		}
		return nil
	})

	g.Go(func() (err error) {
		s.allNamespaces, err = client.CoreV1().Namespaces().List(gCtx, metav1.ListOptions{
			ResourceVersion: "0",
		})
		if err != nil {
			return fmt.Errorf("list namespaces from API: %w", err)
		}
		return nil
	})

	g.Go(func() (err error) {
		s.dbNodes, err = cacheStore.ListNodes(gCtx)
		if err != nil {
			return fmt.Errorf("list cached nodes: %w", err)
		}
		return nil
	})

	g.Go(func() (err error) {
		s.dbPodStates, err = cacheStore.ListPodStates(gCtx)
		if err != nil {
			return fmt.Errorf("list cached pod states: %w", err)
		}
		return nil
	})

	g.Go(func() (err error) {
		s.dispatchJobs, err = dispatchStore.ListDispatchJobs(gCtx)
		if err != nil {
			return fmt.Errorf("list dispatcher job state: %w", err)
		}
		return nil
	})

	g.Go(func() (err error) {
		s.dispatchPods, err = dispatchStore.ListDispatchPods(gCtx)
		if err != nil {
			return fmt.Errorf("list dispatcher pod state: %w", err)
		}
		return nil
	})

	g.Go(func() (err error) {
		s.dispatchNamespaces, err = dispatchStore.ListDispatchNamespaces(gCtx)
		if err != nil {
			return fmt.Errorf("list dispatcher namespace state: %w", err)
		}
		return nil
	})

	g.Go(func() (err error) {
		s.assumedKeys, err = cacheStore.ListAssumedPodKeys(gCtx)
		if err != nil {
			return fmt.Errorf("list assumed pod keys: %w", err)
		}
		return nil
	})

	// PriorityQueue.PendingPods() returns ([]*v1.Pod, string), no error.
	g.Go(func() error {
		s.pendingPods, s.pendingSummary = q.PendingPods()
		return nil
	})

	return s, g.Wait()
}

// Reconcile is the main entrypoint used by the Lambda starter/handler.
// It orchestrates the full reconciliation flow while delegating each phase
// to focused helper functions for readability.
func Reconcile(
	ctx context.Context,
	logger klog.Logger,
	client kubernetes.Interface,
	cacheStore *awsstore.CacheStore,
	dispatchStore *awsstore.DispatcherStore,
	q queue.SchedulingQueue,
	controllerQueues ControllerQueues,
) (Result, error) {
	logger.Info("Starting dispatcher reconcile loop")

	// The scheduling queue is shared across warm Lambda invocations, so its
	// per-invocation namespace label cache must be cleared at the start of
	// every reconcile. Without this the cache would be effectively process-
	// scoped and serve stale labels.
	q.ResetNamespaceLabelsCache()

	state, err := fetchAll(ctx, client, cacheStore, dispatchStore, q)
	if err != nil {
		return Result{}, err
	}
	logger.V(5).Info("Fetched scheduler repair snapshot", "pending", state.pendingSummary)

	run := newReconcileRun(logger, cacheStore, dispatchStore, q, controllerQueues, state, time.Now())

	run.reconcileNodes()
	run.reconcileScheduledPods()
	run.applyNodePodDeltas()
	run.reconcileUnscheduledPods()

	if err := run.persist(ctx); err != nil {
		return run.res, err
	}
	if err := run.dispatchControllerEvents(ctx); err != nil {
		return run.res, err
	}
	if err := run.persistDispatchState(ctx); err != nil {
		return run.res, err
	}

	logger.Info(
		"Completed dispatcher reconcile loop",
		"pending", state.pendingSummary,
		"nodesAdded", run.res.NodesAdded,
		"nodesUpdated", run.res.NodesUpdated,
		"nodesDeleted", run.res.NodesDeleted,
		"podsAdded", run.res.PodsAdded,
		"podsUpdated", run.res.PodsUpdated,
		"podsDeleted", run.res.PodsDeleted,
		"podsEnqueued", run.res.PodsEnqueued,
		"jobSyncsEnqueued", run.res.JobSyncsEnqueued,
		"jobOrphansEnqueued", run.res.JobOrphansEnqueued,
		"ttlJobsEnqueued", run.res.TTLJobsEnqueued,
		"namespacesEnqueued", run.res.NamespacesEnqueued,
	)

	return run.res, nil
}

func newReconcileRun(
	logger klog.Logger,
	cacheStore *awsstore.CacheStore,
	dispatchStore *awsstore.DispatcherStore,
	q queue.SchedulingQueue,
	controllerQueues ControllerQueues,
	state clusterState,
	now time.Time,
) *reconcileRun {
	podIdx := indexPods(logger, state.allPods)
	jobsByKey, jobMatchers := indexJobsAndSelectors(logger, state.allJobs)

	return &reconcileRun{
		logger:           logger,
		cacheStore:       cacheStore,
		dispatchStore:    dispatchStore,
		schedulingQueue:  q,
		controllerQueues: controllerQueues,
		state:            state,
		now:              now,

		k8sNodeMap:      indexNodes(state.k8sNodes),
		allPodsByKey:    podIdx.byDispatchKey,
		jobs:            jobsByKey,
		jobMatchers:     jobMatchers,
		namespaces:      indexNamespaces(state.allNamespaces),
		assumed:         indexAssumedKeys(state.assumedKeys),
		scheduledPods:   podIdx.scheduled,
		unscheduledPods: podIdx.unscheduled,
		pendingMap:      indexPendingPods(logger, state.pendingPods),

		dirtyNodes:              make(map[string]*awsstore.NodeRecord, len(state.dbNodes)),
		deletedNodes:            make(map[string]struct{}),
		dirtyPodStates:          make(map[string]*awsstore.PodStateRecord, len(state.dbPodStates)),
		deletedPodStates:        make(map[string]struct{}),
		deletedAssumedKeys:      make(map[string]struct{}),
		nodePodDeltas:           make(map[string]*nodePodDelta),
		nodePodOps:              make(map[string]*nodePodPersistOps),
		dirtyDispatchJobs:       make(map[string]*awsstore.DispatchJobState),
		deletedDispatchJobs:     make(map[string]struct{}),
		dirtyDispatchPods:       make(map[string]*awsstore.DispatchPodState),
		deletedDispatchPods:     make(map[string]struct{}),
		dirtyDispatchNamespaces: make(map[string]*awsstore.DispatchNamespaceState),
		deletedDispatchNS:       make(map[string]struct{}),
	}
}

func (r *reconcileRun) reconcileNodes() {
	for name, node := range r.k8sNodeMap {
		existing, inDB := r.state.dbNodes[name]
		if !inDB || existing == nil || existing.Node == nil {
			rec := awsstore.NewNodeRecord()
			rec.Node = node
			rec.UpdatedAt = r.now
			r.state.dbNodes[name] = rec
			r.dirtyNodes[name] = rec

			r.schedulingQueue.MoveAllToActiveOrBackoffQueue(
				r.logger,
				framework.ClusterEvent{Resource: framework.Node, ActionType: framework.Add},
				nil,
				node,
				nil,
			)
			r.res.NodesAdded++
			continue
		}

		if node.ResourceVersion == existing.Node.ResourceVersion {
			continue
		}

		oldNode := existing.Node
		existing.Node = node
		existing.Generation++
		existing.UpdatedAt = r.now
		r.dirtyNodes[name] = existing

		for _, evt := range framework.NodeSchedulingPropertiesChange(node, oldNode) {
			r.schedulingQueue.MoveAllToActiveOrBackoffQueue(r.logger, evt, oldNode, node, nil)
		}
		r.res.NodesUpdated++
	}

	for name, rec := range r.state.dbNodes {
		if _, ok := r.k8sNodeMap[name]; ok {
			continue
		}
		if rec != nil && rec.Node != nil {
			r.schedulingQueue.MoveAllToActiveOrBackoffQueue(
				r.logger,
				framework.ClusterEvent{Resource: framework.Node, ActionType: framework.Delete},
				rec.Node,
				nil,
				nil,
			)
		}
		r.deletedNodes[name] = struct{}{}
		r.res.NodesDeleted++
	}

	for name := range r.deletedNodes {
		delete(r.state.dbNodes, name)
		delete(r.dirtyNodes, name)
	}
}

func (r *reconcileRun) reconcileScheduledPods() {
	for key, pod := range r.scheduledPods {
		if _, isAssumed := r.assumed[key]; isAssumed {
			// K8s has confirmed this assumed pod as scheduled. There is no
			// TTL goroutine and no informer-driven AddPod() in the Lambda
			// scheduler, so the dispatcher is the only place that can
			// promote an assumed pod to a fully-confirmed scheduled pod.
			// Remove the assumed key from memory so the existing logic below
			// processes it normally, and schedule the DB deletion.
			delete(r.assumed, key)
			r.deletedAssumedKeys[key] = struct{}{}
		}

		existing, inDB := r.state.dbPodStates[key]
		if !inDB || existing == nil || existing.Pod == nil {
			r.dirtyPodStates[key] = &awsstore.PodStateRecord{Pod: pod}
			markNodeAdd(r.nodePodDeltas, pod)
			notifyAssignedPodAdd(r.logger, r.schedulingQueue, pod)
			r.res.PodsAdded++
			continue
		}

		if pod.ResourceVersion == existing.Pod.ResourceVersion {
			continue
		}

		oldPod := existing.Pod
		existing.Pod = pod
		r.dirtyPodStates[key] = existing

		if oldPod.Spec.NodeName == pod.Spec.NodeName && pod.Spec.NodeName != "" {
			markNodeReplace(r.nodePodDeltas, oldPod, pod)
		} else {
			markNodeDel(r.nodePodDeltas, oldPod)
			markNodeAdd(r.nodePodDeltas, pod)
		}

		notifyAssignedPodUpdate(r.logger, r.schedulingQueue, oldPod, pod)
		r.res.PodsUpdated++
	}

	for key, rec := range r.state.dbPodStates {
		if _, isAssumed := r.assumed[key]; isAssumed {
			_, inK8s := r.scheduledPods[key]
			if !inK8s && rec != nil {
				stale := rec.BindingFinished || (rec.Deadline != nil && r.now.After(*rec.Deadline))
				if stale {
					// Assumed pod completed and was deleted from K8s (e.g. by PodGC)
					// before the dispatcher observed it as scheduled. Clean up the
					// phantom entry so its resources are freed from the node record.
					delete(r.assumed, key)
					r.deletedAssumedKeys[key] = struct{}{}
					r.deletedPodStates[key] = struct{}{}
					if rec.Pod != nil {
						markNodeDel(r.nodePodDeltas, rec.Pod)
					}
				}
			}
			continue
		}
		if _, inK8s := r.scheduledPods[key]; inK8s {
			continue
		}

		r.deletedPodStates[key] = struct{}{}
		if rec != nil && rec.Pod != nil {
			markNodeDel(r.nodePodDeltas, rec.Pod)
			r.schedulingQueue.MoveAllToActiveOrBackoffQueue(r.logger, framework.EventAssignedPodDelete, rec.Pod, nil, nil)
		}
		r.res.PodsDeleted++
	}
}

func (r *reconcileRun) applyNodePodDeltas() {
	for nodeName, delta := range r.nodePodDeltas {
		// Nodes that are being deleted will have all their per-pod records
		// purged by DeleteNode in persist(); skip emitting individual pod ops.
		if _, deleted := r.deletedNodes[nodeName]; deleted {
			continue
		}

		rec, ok := r.state.dbNodes[nodeName]
		if !ok || rec == nil {
			continue
		}

		ops := r.getNodePodOps(nodeName)

		// Per-pod items are keyed by pod UID, so a "replace" of the same pod
		// (same UID, new ResourceVersion) is just an upsert that overwrites
		// the prior payload.
		for _, repl := range delta.replace {
			ops.upsert = append(ops.upsert, repl.newPod)
		}

		for _, pod := range delta.del {
			key, err := framework.GetPodKey(pod)
			if err != nil {
				r.logger.Error(err, "Failed to get pod key for node delta delete", "pod", klog.KObj(pod), "node", nodeName)
				continue
			}
			ops.delete = append(ops.delete, key)
		}

		for _, pod := range delta.add {
			ops.upsert = append(ops.upsert, pod)
		}

		// Bump the node-meta generation so consumers calling ListNodes /
		// UpdateSnapshot observe a fresh version after the pod set changes.
		rec.Generation++
		rec.UpdatedAt = r.now
		r.dirtyNodes[nodeName] = rec
	}
}

func (r *reconcileRun) getNodePodOps(nodeName string) *nodePodPersistOps {
	ops, ok := r.nodePodOps[nodeName]
	if !ok {
		ops = &nodePodPersistOps{}
		r.nodePodOps[nodeName] = ops
	}
	return ops
}

func (r *reconcileRun) reconcileUnscheduledPods() {
	for key, pod := range r.unscheduledPods {
		if _, isAssumed := r.assumed[key]; isAssumed {
			continue
		}

		existing, isPending := r.pendingMap[key]
		if !isPending {
			r.schedulingQueue.Add(r.logger, pod)
			r.res.PodsEnqueued++
			continue
		}

		// Always call Update() even when ResourceVersion is unchanged.
		// This increments the DynamoDB item version, generating a MODIFY stream
		// event that re-triggers scheduleOne for items whose INSERT events were
		// already consumed by earlier invocations that processed higher-priority
		// queue entries ("signal theft").
		r.schedulingQueue.Update(r.logger, existing, pod)
		if hasNominatedNodeNameChanged(existing, pod) {
			r.schedulingQueue.MoveAllToActiveOrBackoffQueue(
				r.logger,
				framework.EventAssignedPodDelete,
				existing,
				nil,
				getLEPriorityPreCheck(corev1helpers.PodPriority(existing)),
			)
		}
		r.res.PodsEnqueued++
	}

	for key, pod := range r.pendingMap {
		if _, isAssumed := r.assumed[key]; isAssumed {
			continue
		}
		if _, inK8s := r.unscheduledPods[key]; inK8s {
			continue
		}

		r.schedulingQueue.Delete(pod)

		// Exact upstream parity also checks RejectWaitingPod(pod.UID),
		// which requires framework access not present in this dispatcher.
		if pod.Status.NominatedNodeName != "" {
			r.schedulingQueue.MoveAllToActiveOrBackoffQueue(
				r.logger,
				framework.EventAssignedPodDelete,
				pod,
				nil,
				getLEPriorityPreCheck(corev1helpers.PodPriority(pod)),
			)
		}
	}
}

func (r *reconcileRun) persist(ctx context.Context) error {
	writeGroup, writeCtx := errgroup.WithContext(ctx)
	writeGroup.SetLimit(16)

	for name, rec := range r.dirtyNodes {
		name, rec := name, rec
		writeGroup.Go(func() error {
			if err := r.cacheStore.UpsertNodeMeta(writeCtx, name, rec); err != nil {
				return fmt.Errorf("upsert node meta %s: %w", name, err)
			}
			return nil
		})
	}

	for nodeName, ops := range r.nodePodOps {
		nodeName, ops := nodeName, ops
		writeGroup.Go(func() error {
			for _, pod := range ops.upsert {
				if err := r.cacheStore.AddNodePod(writeCtx, nodeName, pod); err != nil {
					return fmt.Errorf("upsert pod on node %s: %w", nodeName, err)
				}
			}
			for _, key := range ops.delete {
				if _, err := r.cacheStore.RemoveNodePod(writeCtx, nodeName, key); err != nil {
					return fmt.Errorf("remove pod %s on node %s: %w", key, nodeName, err)
				}
			}
			return nil
		})
	}

	for name := range r.deletedNodes {
		name := name
		writeGroup.Go(func() error {
			if _, err := r.cacheStore.DeleteNode(writeCtx, name); err != nil {
				return fmt.Errorf("delete node %s: %w", name, err)
			}
			return nil
		})
	}

	for key, rec := range r.dirtyPodStates {
		key, rec := key, rec
		writeGroup.Go(func() error {
			if err := r.cacheStore.UpsertPodState(writeCtx, key, rec); err != nil {
				return fmt.Errorf("upsert pod state %s: %w", key, err)
			}
			return nil
		})
	}

	for key := range r.deletedPodStates {
		key := key
		writeGroup.Go(func() error {
			if _, err := r.cacheStore.DeletePodState(writeCtx, key); err != nil {
				return fmt.Errorf("delete pod state %s: %w", key, err)
			}
			return nil
		})
	}

	for key := range r.deletedAssumedKeys {
		key := key
		writeGroup.Go(func() error {
			if _, err := r.cacheStore.DeleteAssumedPod(writeCtx, key); err != nil {
				return fmt.Errorf("delete assumed pod key %s: %w", key, err)
			}
			return nil
		})
	}

	return writeGroup.Wait()
}

func (r *reconcileRun) persistDispatchState(ctx context.Context) error {
	writeGroup, writeCtx := errgroup.WithContext(ctx)
	writeGroup.SetLimit(16)

	for key, rec := range r.dirtyDispatchJobs {
		key, rec := key, rec
		writeGroup.Go(func() error {
			if err := r.dispatchStore.UpsertDispatchJob(writeCtx, key, rec); err != nil {
				return fmt.Errorf("upsert dispatch job %s: %w", key, err)
			}
			return nil
		})
	}

	for key := range r.deletedDispatchJobs {
		key := key
		writeGroup.Go(func() error {
			if _, err := r.dispatchStore.DeleteDispatchJob(writeCtx, key); err != nil {
				return fmt.Errorf("delete dispatch job %s: %w", key, err)
			}
			return nil
		})
	}

	for key, rec := range r.dirtyDispatchPods {
		key, rec := key, rec
		writeGroup.Go(func() error {
			if err := r.dispatchStore.UpsertDispatchPod(writeCtx, key, rec); err != nil {
				return fmt.Errorf("upsert dispatch pod %s: %w", key, err)
			}
			return nil
		})
	}

	for key := range r.deletedDispatchPods {
		key := key
		writeGroup.Go(func() error {
			if _, err := r.dispatchStore.DeleteDispatchPod(writeCtx, key); err != nil {
				return fmt.Errorf("delete dispatch pod %s: %w", key, err)
			}
			return nil
		})
	}

	for key, rec := range r.dirtyDispatchNamespaces {
		key, rec := key, rec
		writeGroup.Go(func() error {
			if err := r.dispatchStore.UpsertDispatchNamespace(writeCtx, key, rec); err != nil {
				return fmt.Errorf("upsert dispatch namespace %s: %w", key, err)
			}
			return nil
		})
	}

	for key := range r.deletedDispatchNS {
		key := key
		writeGroup.Go(func() error {
			if _, err := r.dispatchStore.DeleteDispatchNamespace(writeCtx, key); err != nil {
				return fmt.Errorf("delete dispatch namespace %s: %w", key, err)
			}
			return nil
		})
	}

	return writeGroup.Wait()
}
