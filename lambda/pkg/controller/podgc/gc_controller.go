/*
Copyright 2015 The Kubernetes Authors.

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

package podgc

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"

	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	apipod "k8s.io/kubernetes/pkg/api/v1/pod"
	"k8s.io/kubernetes/pkg/kubelet/eviction"
	nodeutil "k8s.io/kubernetes/pkg/util/node"
	utilpod "k8s.io/kubernetes/pkg/util/pod"
	"k8s.io/kubernetes/pkg/util/taints"
)

const DefaultTerminatedPodThreshold = 0

type Result struct {
	PodsListed         int `json:"podsListed"`
	NodesListed        int `json:"nodesListed"`
	TerminatedDeleted  int `json:"terminatedDeleted"`
	TerminatingDeleted int `json:"terminatingDeleted"`
	OrphanedDeleted    int `json:"orphanedDeleted"`
	UnscheduledDeleted int `json:"unscheduledDeleted"`
}

type PodGCController struct {
	kubeClient kubernetes.Interface

	terminatedPodThreshold int
}

func NewPodGC(kubeClient kubernetes.Interface, terminatedPodThreshold int) (*PodGCController, error) {
	if kubeClient == nil {
		return nil, fmt.Errorf("nil kube client")
	}
	return &PodGCController{
		kubeClient:             kubeClient,
		terminatedPodThreshold: terminatedPodThreshold,
	}, nil
}

func (gcc *PodGCController) RunOnce(ctx context.Context) (Result, error) {
	logger := klog.FromContext(ctx)

	pods, err := gcc.listPods(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("list pods: %w", err)
	}
	nodes, err := gcc.listNodes(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("list nodes: %w", err)
	}

	result := Result{
		PodsListed:  len(pods),
		NodesListed: len(nodes),
	}
	var errs []error

	// Make it always run
	if gcc.terminatedPodThreshold > -1 {
		n, gcErr := gcc.gcTerminated(ctx, pods)
		result.TerminatedDeleted = n
		if gcErr != nil {
			errs = append(errs, gcErr)
		}
	}

	n, gcErr := gcc.gcTerminating(ctx, pods)
	result.TerminatingDeleted = n
	if gcErr != nil {
		errs = append(errs, gcErr)
	}

	n, gcErr = gcc.gcOrphaned(ctx, pods, nodes)
	result.OrphanedDeleted = n
	if gcErr != nil {
		errs = append(errs, gcErr)
	}

	n, gcErr = gcc.gcUnscheduledTerminating(ctx, pods)
	result.UnscheduledDeleted = n
	if gcErr != nil {
		errs = append(errs, gcErr)
	}

	logger.Info(
		"PodGC invocation completed",
		"podsListed", result.PodsListed,
		"nodesListed", result.NodesListed,
		"terminatedDeleted", result.TerminatedDeleted,
		"terminatingDeleted", result.TerminatingDeleted,
		"orphanedDeleted", result.OrphanedDeleted,
		"unscheduledDeleted", result.UnscheduledDeleted,
	)

	return result, errors.Join(errs...)
}

func (gcc *PodGCController) listPods(ctx context.Context) ([]*v1.Pod, error) {
	podList, err := gcc.kubeClient.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	pods := make([]*v1.Pod, 0, len(podList.Items))
	for i := range podList.Items {
		pods = append(pods, &podList.Items[i])
	}
	return pods, nil
}

func (gcc *PodGCController) listNodes(ctx context.Context) ([]*v1.Node, error) {
	nodeList, err := gcc.kubeClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	nodes := make([]*v1.Node, 0, len(nodeList.Items))
	for i := range nodeList.Items {
		nodes = append(nodes, &nodeList.Items[i])
	}
	return nodes, nil
}

func isPodTerminated(pod *v1.Pod) bool {
	if phase := pod.Status.Phase; phase != v1.PodPending && phase != v1.PodRunning && phase != v1.PodUnknown {
		return true
	}
	return false
}

// isPodTerminating returns true if the pod is terminating.
func isPodTerminating(pod *v1.Pod) bool {
	return pod.ObjectMeta.DeletionTimestamp != nil
}

func (gcc *PodGCController) gcTerminating(ctx context.Context, pods []*v1.Pod) (int, error) {
	logger := klog.FromContext(ctx)
	logger.V(4).Info("GC'ing terminating pods that are on out-of-service nodes")
	terminatingPods := []*v1.Pod{}
	for _, pod := range pods {
		if !isPodTerminating(pod) {
			continue
		}
		node, err := gcc.kubeClient.CoreV1().Nodes().Get(ctx, pod.Spec.NodeName, metav1.GetOptions{})
		if err != nil {
			logger.Error(err, "Failed to get node", "node", klog.KRef("", pod.Spec.NodeName))
			continue
		}
		if !nodeutil.IsNodeReady(node) && taints.TaintKeyExists(node.Spec.Taints, v1.TaintNodeOutOfService) {
			logger.V(4).Info("Garbage collecting pod that is terminating", "pod", klog.KObj(pod), "phase", pod.Status.Phase)
			terminatingPods = append(terminatingPods, pod)
		}
	}

	deleteCount := len(terminatingPods)
	if deleteCount == 0 {
		return 0, nil
	}

	logger.V(4).Info("Garbage collecting pods that are terminating on node tainted with node.kubernetes.io/out-of-service", "numPods", deleteCount)
	sort.Sort(byEvictionAndCreationTimestamp(terminatingPods))
	var wait sync.WaitGroup
	errCh := make(chan error, deleteCount)
	for i := 0; i < deleteCount; i++ {
		wait.Add(1)
		go func(pod *v1.Pod) {
			defer wait.Done()
			if err := gcc.markFailedAndDeletePod(ctx, pod); err != nil && !apierrors.IsNotFound(err) {
				errCh <- err
			}
		}(terminatingPods[i])
	}
	wait.Wait()
	return deleteCount - len(errCh), errorsFromChannel(errCh)
}

func (gcc *PodGCController) gcTerminated(ctx context.Context, pods []*v1.Pod) (int, error) {
	terminatedPods := []*v1.Pod{}
	for _, pod := range pods {
		if isPodTerminated(pod) {
			terminatedPods = append(terminatedPods, pod)
		}
	}

	deleteCount := len(terminatedPods) - gcc.terminatedPodThreshold
	if deleteCount <= 0 {
		return 0, nil
	}

	logger := klog.FromContext(ctx)
	logger.Info("Garbage collecting terminated pods", "numPods", deleteCount)
	sort.Sort(byEvictionAndCreationTimestamp(terminatedPods))
	var wait sync.WaitGroup
	errCh := make(chan error, deleteCount)
	for i := 0; i < deleteCount; i++ {
		wait.Add(1)
		go func(pod *v1.Pod) {
			defer wait.Done()
			if err := gcc.markFailedAndDeletePod(ctx, pod); err != nil && !apierrors.IsNotFound(err) {
				errCh <- err
			}
		}(terminatedPods[i])
	}
	wait.Wait()
	return deleteCount - len(errCh), errorsFromChannel(errCh)
}

// gcOrphaned deletes pods that are bound to nodes that don't exist.
func (gcc *PodGCController) gcOrphaned(ctx context.Context, pods []*v1.Pod, nodes []*v1.Node) (int, error) {
	logger := klog.FromContext(ctx)
	logger.V(4).Info("GC'ing orphaned")
	existingNodeNames := sets.NewString()
	for _, node := range nodes {
		existingNodeNames.Insert(node.Name)
	}

	deleted := 0
	var errs []error
	for _, pod := range pods {
		if pod.Spec.NodeName == "" || existingNodeNames.Has(pod.Spec.NodeName) {
			continue
		}
		logger.V(2).Info("Found orphaned Pod assigned to the Node, deleting", "pod", klog.KObj(pod), "node", klog.KRef("", pod.Spec.NodeName))
		condition := &v1.PodCondition{
			Type:               v1.DisruptionTarget,
			ObservedGeneration: apipod.GetPodObservedGenerationIfEnabledOnCondition(&pod.Status, pod.Generation, v1.DisruptionTarget),
			Status:             v1.ConditionTrue,
			Reason:             "DeletionByPodGC",
			Message:            "PodGC: node no longer exists",
		}
		if err := gcc.markFailedAndDeletePodWithCondition(ctx, pod, condition); err != nil && !apierrors.IsNotFound(err) {
			utilruntime.HandleError(err)
			errs = append(errs, err)
		} else {
			deleted++
			logger.Info("Forced deletion of orphaned Pod succeeded", "pod", klog.KObj(pod))
		}
	}
	return deleted, errors.Join(errs...)
}

// gcUnscheduledTerminating deletes pods that are terminating and haven't been scheduled to a particular node.
func (gcc *PodGCController) gcUnscheduledTerminating(ctx context.Context, pods []*v1.Pod) (int, error) {
	logger := klog.FromContext(ctx)
	logger.V(4).Info("GC'ing unscheduled pods which are terminating")

	deleted := 0
	var errs []error
	for _, pod := range pods {
		if pod.DeletionTimestamp == nil || len(pod.Spec.NodeName) > 0 {
			continue
		}

		logger.V(2).Info("Found unscheduled terminating Pod not assigned to any Node, deleting", "pod", klog.KObj(pod))
		if err := gcc.markFailedAndDeletePod(ctx, pod); err != nil && !apierrors.IsNotFound(err) {
			utilruntime.HandleError(err)
			errs = append(errs, err)
		} else {
			deleted++
			logger.Info("Forced deletion of unscheduled terminating Pod succeeded", "pod", klog.KObj(pod))
		}
	}
	return deleted, errors.Join(errs...)
}

// byEvictionAndCreationTimestamp sorts a list by Evicted status and then creation timestamp,
// using their names as a tie breaker.
// Evicted pods will be deleted first to avoid impact on terminated pods created by controllers.
type byEvictionAndCreationTimestamp []*v1.Pod

func (o byEvictionAndCreationTimestamp) Len() int      { return len(o) }
func (o byEvictionAndCreationTimestamp) Swap(i, j int) { o[i], o[j] = o[j], o[i] }

func (o byEvictionAndCreationTimestamp) Less(i, j int) bool {
	iEvicted, jEvicted := eviction.PodIsEvicted(o[i].Status), eviction.PodIsEvicted(o[j].Status)
	if iEvicted != jEvicted {
		return iEvicted
	}
	if o[i].CreationTimestamp.Equal(&o[j].CreationTimestamp) {
		return o[i].Name < o[j].Name
	}
	return o[i].CreationTimestamp.Before(&o[j].CreationTimestamp)
}

func (gcc *PodGCController) markFailedAndDeletePod(ctx context.Context, pod *v1.Pod) error {
	return gcc.markFailedAndDeletePodWithCondition(ctx, pod, nil)
}

func (gcc *PodGCController) markFailedAndDeletePodWithCondition(ctx context.Context, pod *v1.Pod, condition *v1.PodCondition) error {
	logger := klog.FromContext(ctx)
	logger.Info("PodGC is force deleting Pod", "pod", klog.KObj(pod))
	if pod.Status.Phase != v1.PodSucceeded && pod.Status.Phase != v1.PodFailed {
		newStatus := pod.Status.DeepCopy()
		newStatus.Phase = v1.PodFailed
		newStatus.ObservedGeneration = apipod.GetPodObservedGenerationIfEnabled(pod)
		if condition != nil {
			apipod.UpdatePodCondition(newStatus, condition)
		}
		if _, _, _, err := utilpod.PatchPodStatus(ctx, gcc.kubeClient, pod.Namespace, pod.Name, pod.UID, pod.Status, *newStatus); err != nil {
			return err
		}
	}
	return gcc.kubeClient.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name, *metav1.NewDeleteOptions(0))
}

func errorsFromChannel(errCh chan error) error {
	close(errCh)
	var errs []error
	for err := range errCh {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
