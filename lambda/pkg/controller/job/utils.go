package job

import (
	"time"

	batch "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
	podutil "k8s.io/kubernetes/pkg/api/v1/pod"
)

func (jm *Controller) newFailureCondition(reason, message string) *batch.JobCondition {
	cType := batch.JobFailed
	if delayTerminalCondition() {
		cType = batch.JobFailureTarget
	}
	return newCondition(cType, v1.ConditionTrue, reason, message, jm.clock.Now())
}

func (jm *Controller) newSuccessCondition() *batch.JobCondition {
	// Always use SuccessCriteriaMet so the controller goes through the
	// two-step transition (SuccessCriteriaMet → Complete) required by the
	// API server when JobSuccessPolicy is enabled.
	return newCondition(batch.JobSuccessCriteriaMet, v1.ConditionTrue,
		batch.JobReasonCompletionsReached, "Reached expected number of succeeded pods",
		jm.clock.Now())
}

func delayTerminalCondition() bool {
	return false
}

// ensureJobConditionStatus appends or updates an existing job condition of the
// given type with the given status value. Note that this function will not
// append to the conditions list if the new condition's status is false
// (because going from nothing to false is meaningless); it can, however,
// update the status condition to false. The function returns a bool to let the
// caller know if the list was changed (either appended or updated).
func ensureJobConditionStatus(list []batch.JobCondition, cType batch.JobConditionType, status v1.ConditionStatus, reason, message string, now time.Time) ([]batch.JobCondition, bool) {
	if condition := findConditionByType(list, cType); condition != nil {
		if condition.Status != status || condition.Reason != reason || condition.Message != message {
			*condition = *newCondition(cType, status, reason, message, now)
			return list, true
		}
		return list, false
	}
	// A condition with that type doesn't exist in the list.
	if status != v1.ConditionFalse {
		return append(list, *newCondition(cType, status, reason, message, now)), true
	}
	return list, false
}

func isPodFailed(p *v1.Pod, job *batch.Job) bool {
	if p.Status.Phase == v1.PodFailed {
		return true
	}
	if onlyReplaceFailedPods(job) {
		return false
	}
	// Count deleted Pods as failures to account for orphan Pods that
	// never have a chance to reach the Failed phase.
	return p.DeletionTimestamp != nil && p.Status.Phase != v1.PodSucceeded
}

func findConditionByType(list []batch.JobCondition, cType batch.JobConditionType) *batch.JobCondition {
	for i := range list {
		if list[i].Type == cType {
			return &list[i]
		}
	}
	return nil
}

func indexesCount(logger klog.Logger, indexesStr *string, completions int) int {
	if indexesStr == nil {
		return 0
	}
	return parseIndexesFromString(logger, *indexesStr, completions).total()
}

func backoffLimitMetricsLabel(job *batch.Job) string {
	if hasBackoffLimitPerIndex(job) {
		return "perIndex"
	}
	return "global"
}

func countReadyPods(pods []*v1.Pod) int32 {
	cnt := int32(0)
	for _, p := range pods {
		if podutil.IsPodReady(p) {
			cnt++
		}
	}
	return cnt
}

func trackTerminatingPods(job *batch.Job) bool {
	return job.Spec.PodFailurePolicy != nil
}

func onlyReplaceFailedPods(job *batch.Job) bool {
	return job.Spec.PodFailurePolicy != nil
}
