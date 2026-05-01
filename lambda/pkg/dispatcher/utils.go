package dispatcher

import (
	"encoding/json"
	"fmt"
	"lambda/pkg/scheduler/backend/awsstore"
	"lambda/pkg/scheduler/backend/queue"
	"strings"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	corev1helpers "k8s.io/component-helpers/scheduling/corev1"
	"k8s.io/klog/v2"
	jobutil "k8s.io/kubernetes/pkg/controller/job/util"
	"k8s.io/kubernetes/pkg/scheduler/framework"
)

type compiledJobSelector struct {
	job      *batchv1.Job
	selector labels.Selector
}

type podIndexes struct {
	byDispatchKey map[string]*corev1.Pod
	scheduled     map[string]*corev1.Pod
	unscheduled   map[string]*corev1.Pod
}

type nodePodReplace struct {
	oldPod *corev1.Pod
	newPod *corev1.Pod
}

type nodePodDelta struct {
	add     []*corev1.Pod
	del     []*corev1.Pod
	replace []nodePodReplace
}

// nodePodPersistOps captures the per-node pod-item writes that need to be
// applied to DynamoDB during persist(). Because pods are now stored as
// individual items (one per pod, keyed by UID, under CACHE#NODEPOD#<nodeName>),
// the reconciler emits explicit upserts and deletes rather than rewriting the
// node record as a single blob.
type nodePodPersistOps struct {
	upsert []*corev1.Pod
	delete []string
}

func hasNominatedNodeNameChanged(oldPod, newPod *corev1.Pod) bool {
	return len(oldPod.Status.NominatedNodeName) > 0 &&
		oldPod.Status.NominatedNodeName != newPod.Status.NominatedNodeName
}

func getLEPriorityPreCheck(priority int32) queue.PreEnqueueCheck {
	return func(pod *corev1.Pod) bool {
		return corev1helpers.PodPriority(pod) <= priority
	}
}

func notifyAssignedPodAdd(logger klog.Logger, q queue.SchedulingQueue, pod *corev1.Pod) {
	q.AssignedPodAdded(logger, pod)
}

func notifyAssignedPodUpdate(logger klog.Logger, q queue.SchedulingQueue, oldPod, newPod *corev1.Pod) {
	for _, evt := range framework.PodSchedulingPropertiesChange(newPod, oldPod) {
		q.AssignedPodUpdated(logger, oldPod, newPod, evt)
	}
}

func deltaFor(m map[string]*nodePodDelta, nodeName string) *nodePodDelta {
	d := m[nodeName]
	if d == nil {
		d = &nodePodDelta{}
		m[nodeName] = d
	}
	return d
}

func markNodeAdd(deltas map[string]*nodePodDelta, pod *corev1.Pod) {
	if pod == nil || pod.Spec.NodeName == "" {
		return
	}
	deltaFor(deltas, pod.Spec.NodeName).add = append(deltaFor(deltas, pod.Spec.NodeName).add, pod)
}

func markNodeReplace(deltas map[string]*nodePodDelta, oldPod, newPod *corev1.Pod) {
	if oldPod == nil || newPod == nil {
		return
	}
	if oldPod.Spec.NodeName == "" || newPod.Spec.NodeName == "" {
		return
	}
	if oldPod.Spec.NodeName != newPod.Spec.NodeName {
		return
	}

	d := deltaFor(deltas, newPod.Spec.NodeName)
	d.replace = append(d.replace, nodePodReplace{
		oldPod: oldPod,
		newPod: newPod,
	})
}

func markNodeDel(deltas map[string]*nodePodDelta, pod *corev1.Pod) {
	if pod == nil || pod.Spec.NodeName == "" {
		return
	}
	deltaFor(deltas, pod.Spec.NodeName).del = append(deltaFor(deltas, pod.Spec.NodeName).del, pod)
}

func indexNodes(nodes *corev1.NodeList) map[string]*corev1.Node {
	out := make(map[string]*corev1.Node)
	if nodes == nil {
		return out
	}

	for i := range nodes.Items {
		n := &nodes.Items[i]
		out[n.Name] = n
	}

	return out
}

func indexAssumedKeys(keys []string) map[string]struct{} {
	out := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		out[key] = struct{}{}
	}
	return out
}

func indexPendingPods(logger klog.Logger, pendingPods []*corev1.Pod) map[string]*corev1.Pod {
	out := make(map[string]*corev1.Pod, len(pendingPods))

	for _, pod := range pendingPods {
		key, err := framework.GetPodKey(pod)
		if err != nil {
			logger.Error(err, "Failed to get pending pod key", "pod", klog.KObj(pod))
			continue
		}
		out[key] = pod
	}

	return out
}

func controllerKey(obj any) (string, error) {
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		return "", fmt.Errorf("build controller key: %w", err)
	}
	return key, nil
}

func indexNamespaces(namespaceList *corev1.NamespaceList) map[string]*corev1.Namespace {
	out := make(map[string]*corev1.Namespace)
	if namespaceList == nil {
		return out
	}

	for i := range namespaceList.Items {
		namespace := &namespaceList.Items[i]
		out[namespace.Name] = namespace
	}

	return out
}

func (r *reconcileRun) getMatchingJobsForPod(pod *corev1.Pod) []*batchv1.Job {
	if pod == nil {
		return nil
	}

	matchers := r.jobMatchers[pod.Namespace]
	if len(matchers) == 0 {
		return nil
	}

	podLabels := labels.Set(pod.Labels)
	matches := make([]*batchv1.Job, 0, len(matchers))

	for _, matcher := range matchers {
		if matcher.selector.Matches(podLabels) {
			matches = append(matches, matcher.job)
		}
	}

	return matches
}

func (r *reconcileRun) resolveJobControllerRef(namespace string, controllerRef *metav1.OwnerReference) *batchv1.Job {
	if controllerRef == nil || controllerRef.Kind != "Job" || controllerRef.APIVersion != batchv1.SchemeGroupVersion.String() {
		return nil
	}

	key := namespace + "/" + controllerRef.Name
	job, ok := r.jobs[key]
	if !ok || job == nil {
		return nil
	}
	if job.UID != controllerRef.UID {
		return nil
	}
	return job
}

func shouldEnqueueOrphanPod(jobs map[string]*batchv1.Job, pod *corev1.Pod) bool {
	if pod == nil || !hasJobTrackingFinalizer(pod) {
		return false
	}

	controllerRef := metav1.GetControllerOf(pod)
	if controllerRef == nil {
		return true
	}
	if controllerRef.Kind != "Job" || controllerRef.APIVersion != batchv1.SchemeGroupVersion.String() {
		return false
	}

	job, ok := jobs[pod.Namespace+"/"+controllerRef.Name]
	if !ok || job == nil || job.UID != controllerRef.UID {
		return true
	}

	return jobutil.IsJobFinished(job)
}

func jobNeedsCleanup(job *batchv1.Job) bool {
	return job != nil && job.Spec.TTLSecondsAfterFinished != nil && jobutil.IsJobFinished(job)
}

func hasJobTrackingFinalizer(pod *corev1.Pod) bool {
	if pod == nil {
		return false
	}
	for _, finalizer := range pod.Finalizers {
		if finalizer == batchv1.JobTrackingFinalizer {
			return true
		}
	}
	return false
}

func encodeOrphanPodMessage(kind, namespace, value string) (string, error) {
	msg := map[string]string{
		"kind":      strings.TrimSpace(kind),
		"namespace": strings.TrimSpace(namespace),
		"value":     strings.TrimSpace(value),
	}
	if msg["kind"] == "" || msg["namespace"] == "" || msg["value"] == "" {
		return "", fmt.Errorf("orphan pod message requires kind, namespace, and value")
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func jobEventDedupKey(prefix, key string, job *batchv1.Job) string {
	if job == nil {
		return prefix + ":" + key
	}
	return fmt.Sprintf("%s:%s:%s:%s", prefix, key, job.UID, job.ResourceVersion)
}

func namespaceEventDedupKey(namespace *corev1.Namespace) string {
	if namespace == nil {
		return "namespace"
	}
	return fmt.Sprintf("namespace:%s:%s:%s", namespace.Name, namespace.UID, namespace.ResourceVersion)
}

func podEventDedupKey(prefix string, pod *corev1.Pod) string {
	if pod == nil {
		return prefix
	}
	return fmt.Sprintf("%s:%s/%s:%s:%s", prefix, pod.Namespace, pod.Name, pod.UID, pod.ResourceVersion)
}

func deletedObjectDedupKey(prefix, key string, uid types.UID, rv string) string {
	return fmt.Sprintf("%s:%s:%s:%s", prefix, key, uid, rv)
}

func sameOwnerRef(a, b *metav1.OwnerReference) bool {
	switch {
	case a == nil && b == nil:
		return true
	case a == nil || b == nil:
		return false
	default:
		return a.APIVersion == b.APIVersion &&
			a.Kind == b.Kind &&
			a.Name == b.Name &&
			a.UID == b.UID &&
			ptrBoolValue(a.Controller) == ptrBoolValue(b.Controller)
	}
}

func ptrBoolValue(v *bool) bool {
	if v == nil {
		return false
	}
	return *v
}

func indexJobsAndSelectors(
	logger klog.Logger,
	jobList *batchv1.JobList,
) (map[string]*batchv1.Job, map[string][]compiledJobSelector) {
	jobsByKey := make(map[string]*batchv1.Job)
	matchersByNamespace := make(map[string][]compiledJobSelector)

	if jobList == nil {
		return jobsByKey, matchersByNamespace
	}

	for i := range jobList.Items {
		job := &jobList.Items[i]

		key, err := controllerKey(job)
		if err != nil {
			logger.Error(err, "Failed to get controller job key", "job", klog.KObj(job))
		} else {
			jobsByKey[key] = job
		}

		if job.Spec.Selector == nil {
			continue
		}

		selector, err := metav1.LabelSelectorAsSelector(job.Spec.Selector)
		if err != nil || selector.Empty() {
			continue
		}

		matchersByNamespace[job.Namespace] = append(
			matchersByNamespace[job.Namespace],
			compiledJobSelector{
				job:      job,
				selector: selector,
			},
		)
	}

	return jobsByKey, matchersByNamespace
}

func indexPods(logger klog.Logger, allPods *corev1.PodList) podIndexes {
	out := podIndexes{
		byDispatchKey: make(map[string]*corev1.Pod),
		scheduled:     make(map[string]*corev1.Pod),
		unscheduled:   make(map[string]*corev1.Pod),
	}

	if allPods == nil {
		return out
	}

	for i := range allPods.Items {
		pod := &allPods.Items[i]

		// Preserve dispatch-key behavior independently.
		dispatchKey, err := controllerKey(pod)
		if err != nil {
			logger.Error(err, "Failed to get controller pod key", "pod", klog.KObj(pod))
		} else {
			out.byDispatchKey[dispatchKey] = pod
		}

		// Preserve scheduler-key behavior independently.
		schedulerKey, err := framework.GetPodKey(pod)
		if err != nil {
			logger.Error(err, "Failed to get pod key", "pod", klog.KObj(pod))
			continue
		}

		if pod.Spec.NodeName == "" {
			out.unscheduled[schedulerKey] = pod
			continue
		}

		if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
			// Keep existing semantics: terminal scheduled pods are excluded.
			continue
		}

		out.scheduled[schedulerKey] = pod
	}

	return out
}

func podStateControllerRef(pod *awsstore.DispatchPodState) *metav1.OwnerReference {
	if pod == nil {
		return nil
	}
	for i := range pod.OwnerReferences {
		ref := &pod.OwnerReferences[i]
		if ref.Controller != nil && *ref.Controller {
			return ref
		}
	}
	return nil
}

func podStateHasJobTrackingFinalizer(pod *awsstore.DispatchPodState) bool {
	if pod == nil {
		return false
	}
	for _, finalizer := range pod.Finalizers {
		if finalizer == batchv1.JobTrackingFinalizer {
			return true
		}
	}
	return false
}

func podStateEventDedupKey(prefix string, pod *awsstore.DispatchPodState) string {
	if pod == nil {
		return prefix
	}
	return fmt.Sprintf("%s:%s/%s:%s:%s", prefix, pod.Namespace, pod.Name, pod.UID, pod.ResourceVersion)
}

func (r *reconcileRun) enqueueOrphanPodStateByName(
	n *controllerNotifications,
	pod *awsstore.DispatchPodState,
	reason string,
) {
	if pod == nil {
		return
	}
	body, err := encodeOrphanPodMessage("name", pod.Namespace, pod.Name)
	if err != nil {
		r.logger.Error(err, "Failed to encode orphan pod notification", "namespace", pod.Namespace, "name", pod.Name)
		return
	}
	n.jobOrphan.add(body, podStateEventDedupKey(reason, pod), 0)
}
