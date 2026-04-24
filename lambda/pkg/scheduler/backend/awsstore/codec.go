package awsstore

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/kubernetes/pkg/scheduler/framework"
)

type queuedPodInfoWire struct {
	Pod                     *corev1.Pod `json:"pod"`
	Timestamp               time.Time   `json:"timestamp"`
	InitialAttemptTimestamp *time.Time  `json:"initialAttemptTimestamp,omitempty"`
	Attempts                int         `json:"attempts"`
	BackoffExpiration       time.Time   `json:"backoffExpiration,omitempty"`
	UnschedulablePlugins    []string    `json:"unschedulablePlugins,omitempty"`
	PendingPlugins          []string    `json:"pendingPlugins,omitempty"`
	Gated                   bool        `json:"gated,omitempty"`
}

func MarshalQueuedPodInfo(pInfo *framework.QueuedPodInfo) ([]byte, error) {
	if pInfo == nil || pInfo.PodInfo == nil || pInfo.Pod == nil {
		return nil, fmt.Errorf("nil queued pod info")
	}

	var initialAttempt *time.Time
	if pInfo.InitialAttemptTimestamp != nil {
		t := *pInfo.InitialAttemptTimestamp
		initialAttempt = &t
	}

	wire := queuedPodInfoWire{
		Pod:                     pInfo.Pod.DeepCopy(),
		Timestamp:               pInfo.Timestamp,
		InitialAttemptTimestamp: initialAttempt,
		Attempts:                pInfo.Attempts,
		BackoffExpiration:       pInfo.BackoffExpiration,
		UnschedulablePlugins:    setToSortedSlice(pInfo.UnschedulablePlugins),
		PendingPlugins:          setToSortedSlice(pInfo.PendingPlugins),
		Gated:                   pInfo.Gated,
	}

	data, err := json.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("marshal queued pod info: %w", err)
	}
	return data, nil
}

func UnmarshalQueuedPodInfo(data []byte) (*framework.QueuedPodInfo, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty queued pod info payload")
	}

	var wire queuedPodInfoWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, fmt.Errorf("unmarshal queued pod info: %w", err)
	}
	if wire.Pod == nil {
		return nil, fmt.Errorf("queued pod info payload missing pod")
	}

	// Rebuild derived PodInfo fields from Pod.
	podInfo, err := framework.NewPodInfo(wire.Pod)
	if err != nil {
		return nil, fmt.Errorf("build PodInfo for pod %s/%s: %w", wire.Pod.Namespace, wire.Pod.Name, err)
	}
	if podInfo == nil {
		return nil, fmt.Errorf("build PodInfo for pod %s/%s returned nil", wire.Pod.Namespace, wire.Pod.Name)
	}

	var initialAttempt *time.Time
	if wire.InitialAttemptTimestamp != nil {
		t := *wire.InitialAttemptTimestamp
		initialAttempt = &t
	}

	return &framework.QueuedPodInfo{
		PodInfo:                 podInfo,
		Timestamp:               wire.Timestamp,
		Attempts:                wire.Attempts,
		BackoffExpiration:       wire.BackoffExpiration,
		InitialAttemptTimestamp: initialAttempt,
		UnschedulablePlugins:    sets.New[string](wire.UnschedulablePlugins...),
		PendingPlugins:          sets.New[string](wire.PendingPlugins...),
		Gated:                   wire.Gated,
	}, nil
}

func setToSortedSlice(s sets.Set[string]) []string {
	if len(s) == 0 {
		return nil
	}
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

type PodStateRecord struct {
	Pod             *corev1.Pod `json:"pod"`
	Deadline        *time.Time  `json:"deadline,omitempty"`
	BindingFinished bool        `json:"bindingFinished"`
}

type AssumedPodRecord struct {
	PodKey string `json:"podKey"`
}

type NodeRecord struct {
	Node       *corev1.Node  `json:"node,omitempty"`
	Pods       []*corev1.Pod `json:"pods,omitempty"`
	Generation int64         `json:"generation"`
	UpdatedAt  time.Time     `json:"updatedAt"`
}

func RebuildNodeInfo(rec *NodeRecord) *framework.NodeInfo {
	ni := framework.NewNodeInfo()
	for _, p := range rec.Pods {
		ni.AddPod(p)
	}
	if rec.Node != nil {
		ni.SetNode(rec.Node)
	}
	ni.Generation = rec.Generation
	return ni
}

func marshalJSON(v any) ([]byte, error) {
	return json.Marshal(v)
}

func unmarshalPodStateRecord(data []byte) (*PodStateRecord, error) {
	var out PodStateRecord
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func unmarshalNodeRecord(data []byte) (*NodeRecord, error) {
	var out NodeRecord
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

type DispatchJobState struct {
	Namespace       string    `json:"namespace"`
	Name            string    `json:"name"`
	UID             types.UID `json:"uid"`
	ResourceVersion string    `json:"resourceVersion"`
}

type DispatchNamespaceState struct {
	Name            string    `json:"name"`
	UID             types.UID `json:"uid"`
	ResourceVersion string    `json:"resourceVersion"`
}

type DispatchPodState struct {
	Namespace       string                  `json:"namespace"`
	Name            string                  `json:"name"`
	UID             types.UID               `json:"uid"`
	ResourceVersion string                  `json:"resourceVersion"`
	Labels          map[string]string       `json:"labels,omitempty"`
	Finalizers      []string                `json:"finalizers,omitempty"`
	OwnerReferences []metav1.OwnerReference `json:"ownerReferences,omitempty"`
}

func NewDispatchJobState(job *batchv1.Job) *DispatchJobState {
	if job == nil {
		return nil
	}
	return &DispatchJobState{
		Namespace:       job.Namespace,
		Name:            job.Name,
		UID:             job.UID,
		ResourceVersion: job.ResourceVersion,
	}
}

func NewDispatchNamespaceState(ns *corev1.Namespace) *DispatchNamespaceState {
	if ns == nil {
		return nil
	}
	return &DispatchNamespaceState{
		Name:            ns.Name,
		UID:             ns.UID,
		ResourceVersion: ns.ResourceVersion,
	}
}

func NewDispatchPodState(pod *corev1.Pod) *DispatchPodState {
	if pod == nil {
		return nil
	}
	labelsCopy := make(map[string]string, len(pod.Labels))
	for k, v := range pod.Labels {
		labelsCopy[k] = v
	}
	finalizersCopy := append([]string(nil), pod.Finalizers...)
	ownerRefsCopy := append([]metav1.OwnerReference(nil), pod.OwnerReferences...)

	return &DispatchPodState{
		Namespace:       pod.Namespace,
		Name:            pod.Name,
		UID:             pod.UID,
		ResourceVersion: pod.ResourceVersion,
		Labels:          labelsCopy,
		Finalizers:      finalizersCopy,
		OwnerReferences: ownerRefsCopy,
	}
}

func unmarshalDispatchJobRecord(data []byte) (*DispatchJobState, error) {
	var out DispatchJobState
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func unmarshalDispatchPodRecord(data []byte) (*DispatchPodState, error) {
	var out DispatchPodState
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func unmarshalDispatchNamespaceRecord(data []byte) (*DispatchNamespaceState, error) {
	var out DispatchNamespaceState
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
