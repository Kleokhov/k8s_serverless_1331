package dispatcher

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/sync/errgroup"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/klog/v2"
	jobutil "k8s.io/kubernetes/pkg/controller/job/util"

	"lambda/pkg/scheduler/backend/awsstore"
)

type DedupQueue interface {
	EnqueueAfter(ctx context.Context, body string, delay time.Duration) error
	EnqueueAfterWithDeduplicationID(ctx context.Context, body, deduplicationID string, delay time.Duration) error
}

type ControllerQueues struct {
	Job       DedupQueue
	JobOrphan DedupQueue
	TTL       DedupQueue
	Namespace DedupQueue
}

func (r *reconcileRun) dispatchControllerEvents(ctx context.Context) error {
	n := newControllerNotifications()

	r.collectJobEvents(n)
	r.collectNamespaceEvents(n)
	r.collectPodEvents(n)

	var (
		jobSyncs   int
		jobOrphans int
		ttlJobs    int
		namespaces int
	)

	g, gCtx := errgroup.WithContext(ctx)

	g.Go(func() error {
		count, err := sendNotificationBatch(gCtx, r.controllerQueues.Job, n.job)
		if err != nil {
			return fmt.Errorf("enqueue job controller notifications: %w", err)
		}
		jobSyncs = count
		return nil
	})

	g.Go(func() error {
		count, err := sendNotificationBatch(gCtx, r.controllerQueues.JobOrphan, n.jobOrphan)
		if err != nil {
			return fmt.Errorf("enqueue job orphan notifications: %w", err)
		}
		jobOrphans = count
		return nil
	})

	g.Go(func() error {
		count, err := sendNotificationBatch(gCtx, r.controllerQueues.TTL, n.ttl)
		if err != nil {
			return fmt.Errorf("enqueue ttl notifications: %w", err)
		}
		ttlJobs = count
		return nil
	})

	g.Go(func() error {
		count, err := sendNotificationBatch(gCtx, r.controllerQueues.Namespace, n.namespace)
		if err != nil {
			return fmt.Errorf("enqueue namespace notifications: %w", err)
		}
		namespaces = count
		return nil
	})

	if err := g.Wait(); err != nil {
		return err
	}

	r.res.JobSyncsEnqueued = jobSyncs
	r.res.JobOrphansEnqueued = jobOrphans
	r.res.TTLJobsEnqueued = ttlJobs
	r.res.NamespacesEnqueued = namespaces

	return nil
}

func (r *reconcileRun) collectJobEvents(n *controllerNotifications) {
	for key, job := range r.jobs {
		oldRec, existed := r.state.dispatchJobs[key]
		if existed && oldRec != nil && oldRec.ResourceVersion == job.ResourceVersion {
			continue
		}

		r.dirtyDispatchJobs[key] = awsstore.NewDispatchJobState(job)
		n.job.add(key, jobEventDedupKey("job", key, job), 0)
		if jobNeedsCleanup(job) {
			n.ttl.add(key, jobEventDedupKey("ttl", key, job), 0)
		}
	}

	for key, oldRec := range r.state.dispatchJobs {
		if _, stillPresent := r.jobs[key]; stillPresent {
			continue
		}

		r.deletedDispatchJobs[key] = struct{}{}
		if oldRec != nil {
			n.job.add(key, deletedObjectDedupKey("job-delete", key, oldRec.UID, oldRec.ResourceVersion), 0)
		}
	}
}

func (r *reconcileRun) collectNamespaceEvents(n *controllerNotifications) {
	for key, namespace := range r.namespaces {
		oldRec, existed := r.state.dispatchNamespaces[key]
		if existed && oldRec != nil && oldRec.ResourceVersion == namespace.ResourceVersion {
			continue
		}

		r.dirtyDispatchNamespaces[key] = awsstore.NewDispatchNamespaceState(namespace)
		if namespace.DeletionTimestamp != nil && !namespace.DeletionTimestamp.IsZero() {
			n.namespace.add(key, namespaceEventDedupKey(namespace), 0)
		}
	}

	for key := range r.state.dispatchNamespaces {
		if _, stillPresent := r.namespaces[key]; stillPresent {
			continue
		}
		r.deletedDispatchNS[key] = struct{}{}
	}
}

func (r *reconcileRun) collectPodEvents(n *controllerNotifications) {
	for key, pod := range r.allPodsByKey {
		oldRec, existed := r.state.dispatchPods[key]
		if existed && oldRec != nil && oldRec.ResourceVersion == pod.ResourceVersion {
			if shouldEnqueueOrphanPod(r.jobs, pod) {
				r.enqueueOrphanPodByName(n, pod, "orphan-scan")
			}
			continue
		}

		r.dirtyDispatchPods[key] = awsstore.NewDispatchPodState(pod)
		if !existed || oldRec == nil {
			r.handlePodAdd(pod, n)
		} else {
			r.handlePodUpdateState(oldRec, pod, n)
		}

		if shouldEnqueueOrphanPod(r.jobs, pod) {
			r.enqueueOrphanPodByName(n, pod, "orphan-scan")
		}
	}

	for key, oldRec := range r.state.dispatchPods {
		if _, stillPresent := r.allPodsByKey[key]; stillPresent {
			continue
		}

		r.deletedDispatchPods[key] = struct{}{}
		if oldRec != nil {
			r.handlePodDeleteState(oldRec, n)
		}
	}
}

func (r *reconcileRun) handlePodAdd(pod *corev1.Pod, n *controllerNotifications) {
	if pod == nil {
		return
	}
	if pod.DeletionTimestamp != nil {
		r.handlePodDeleteState(awsstore.NewDispatchPodState(pod), n)
		return
	}

	if controllerRef := metav1.GetControllerOf(pod); controllerRef != nil {
		if job := r.resolveJobControllerRef(pod.Namespace, controllerRef); job != nil {
			r.enqueueJobSyncForJob(n, job, podEventDedupKey("pod-add", pod))
		}
		return
	}

	if hasJobTrackingFinalizer(pod) {
		r.enqueueOrphanPodByName(n, pod, "pod-add")
	}
	for _, job := range r.getMatchingJobsForPod(pod) {
		r.enqueueJobSyncForJob(n, job, podEventDedupKey("pod-add-match", pod))
	}
}

func (r *reconcileRun) handlePodUpdateState(
	oldPod *awsstore.DispatchPodState,
	newPod *corev1.Pod,
	n *controllerNotifications,
) {
	if oldPod == nil || newPod == nil {
		return
	}
	if newPod.ResourceVersion == oldPod.ResourceVersion {
		return
	}
	if newPod.DeletionTimestamp != nil {
		r.handlePodDeleteState(oldPod, n)
		return
	}

	oldControllerRef := podStateControllerRef(oldPod)
	newControllerRef := metav1.GetControllerOf(newPod)
	controllerRefChanged := !sameOwnerRef(oldControllerRef, newControllerRef)

	if controllerRefChanged && oldControllerRef != nil {
		if job := r.resolveJobControllerRef(oldPod.Namespace, oldControllerRef); job != nil {
			r.enqueueJobSyncForJob(n, job, podEventDedupKey("pod-update-old-owner", newPod))
		}
	}

	if newControllerRef != nil {
		if job := r.resolveJobControllerRef(newPod.Namespace, newControllerRef); job != nil {
			r.enqueueJobSyncForJob(n, job, podEventDedupKey("pod-update-owner", newPod))
		}
		return
	}

	if hasJobTrackingFinalizer(newPod) {
		r.enqueueOrphanPodByName(n, newPod, "pod-update")
	}

	labelChanged := !labels.Equals(labels.Set(oldPod.Labels), labels.Set(newPod.Labels))
	if labelChanged || controllerRefChanged {
		for _, job := range r.getMatchingJobsForPod(newPod) {
			r.enqueueJobSyncForJob(n, job, podEventDedupKey("pod-update-match", newPod))
		}
	}
}

func (r *reconcileRun) handlePodDeleteState(
	pod *awsstore.DispatchPodState,
	n *controllerNotifications,
) {
	if pod == nil {
		return
	}

	controllerRef := podStateControllerRef(pod)
	if controllerRef == nil {
		if podStateHasJobTrackingFinalizer(pod) {
			r.enqueueOrphanPodStateByName(n, pod, "pod-delete")
		}
		return
	}

	job := r.resolveJobControllerRef(pod.Namespace, controllerRef)
	if job == nil || jobutil.IsJobFinished(job) {
		if podStateHasJobTrackingFinalizer(pod) {
			r.enqueueOrphanPodStateByName(n, pod, "pod-delete")
		}
		return
	}

	r.enqueueJobSyncForJob(n, job, podStateEventDedupKey("pod-delete-owner", pod))
}

func (r *reconcileRun) enqueueJobSyncForJob(n *controllerNotifications, job *batchv1.Job, dedupKey string) {
	if job == nil {
		return
	}
	key, err := controllerKey(job)
	if err != nil {
		r.logger.Error(err, "Failed to build job key", "job", klog.KObj(job))
		return
	}
	n.job.add(key, dedupKey, 0)
}

func (r *reconcileRun) enqueueOrphanPodByName(n *controllerNotifications, pod *corev1.Pod, reason string) {
	body, err := encodeOrphanPodMessage("name", pod.Namespace, pod.Name)
	if err != nil {
		r.logger.Error(err, "Failed to encode orphan pod notification", "pod", klog.KObj(pod))
		return
	}
	n.jobOrphan.add(body, podEventDedupKey(reason, pod), 0)
}
