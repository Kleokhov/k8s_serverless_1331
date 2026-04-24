/*
Copyright 2024 The Kubernetes Authors.

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

package queue

import (
	"context"
	"encoding/json"
	"lambda/pkg/scheduler/backend/awsstore"
	"sync"

	dbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/scheduler/framework"
)

const (
	nominatorUIDPartitionPrefix  = "NOMINATOR_UID"
	nominatorNodePartitionPrefix = "NOMINATOR_NODE#"
)

// nominator is a structure that stores pods nominated to run on nodes.
// It exists because nominatedNodeName of pod objects stored in the structure
// may be different than what scheduler has here. We should be able to find pods
// by their UID and update/delete them.
type nominator struct {
	nLock      sync.RWMutex
	kubeClient kubernetes.Interface
	store      awsstore.DynamoMap
}

func newPodNominator(kubeClient kubernetes.Interface, store awsstore.DynamoMap) *nominator {
	return &nominator{
		kubeClient: kubeClient,
		store:      store,
	}
}

// AddNominatedPod adds a pod to the nominated pods of the given node.
// This is called during the preemption process after a node is nominated to run
// the pod. We update the structure before sending a request to update the pod
// object to avoid races with the following scheduling cycles.
func (npm *nominator) AddNominatedPod(logger klog.Logger, pi *framework.PodInfo, nominatingInfo *framework.NominatingInfo) {
	npm.nLock.Lock()
	npm.addNominatedPodUnlocked(logger, pi, nominatingInfo)
	npm.nLock.Unlock()
}

func (npm *nominator) addNominatedPodUnlocked(logger klog.Logger, pi *framework.PodInfo, nominatingInfo *framework.NominatingInfo) {
	// Always delete the pod if it already exists, to ensure we never store more than
	// one instance of the pod.
	npm.deleteUnlocked(pi.Pod)

	var nodeName string
	if nominatingInfo.Mode() == framework.ModeOverride {
		nodeName = nominatingInfo.NominatedNodeName
	} else if nominatingInfo.Mode() == framework.ModeNoop {
		if pi.Pod.Status.NominatedNodeName == "" {
			return
		}
		nodeName = pi.Pod.Status.NominatedNodeName
	}

	// Use a live API GET only when needed.
	if npm.kubeClient != nil {
		updatedPod, err := npm.kubeClient.CoreV1().
			Pods(pi.Pod.Namespace).
			Get(context.Background(), pi.Pod.Name, metav1.GetOptions{})
		if err != nil {
			logger.V(4).Info("Pod doesn't exist in API server, aborted adding it to the nominator", "pod", klog.KObj(pi.Pod))
			return
		}
		if updatedPod.Spec.NodeName != "" {
			logger.V(4).Info("Pod is already scheduled to a node, aborted adding it to the nominator", "pod", klog.KObj(pi.Pod), "node", updatedPod.Spec.NodeName)
			return
		}
	}

	ref := podToRef(pi.Pod)
	uidRec := nominatedUIDRecord{
		NodeName: nodeName,
		Ref:      ref,
	}

	uidPayload, err := marshalJSON(uidRec)
	if err != nil {
		return
	}
	nodePayload, err := marshalJSON(ref)
	if err != nil {
		return
	}

	err = npm.store.TransactWrite(context.Background(), []dbtypes.TransactWriteItem{
		npm.store.PutTx(uidPartition(), string(pi.Pod.UID), uidPayload, nil),
		npm.store.PutTx(nodePartition(nodeName), string(pi.Pod.UID), nodePayload, nil),
	})
	if err != nil {
		logger.Error(err, "Failed to add nominated pod to dynamo map", "pod", klog.KObj(pi.Pod), "node", nodeName)
	}
}

// UpdateNominatedPod updates the <oldPod> with <newPod>.
func (npm *nominator) UpdateNominatedPod(logger klog.Logger, oldPod *v1.Pod, newPodInfo *framework.PodInfo) {
	npm.nLock.Lock()
	defer npm.nLock.Unlock()
	var nominatingInfo *framework.NominatingInfo
	if nominatedNodeName(oldPod) == "" && nominatedNodeName(newPodInfo.Pod) == "" {
		item, found, err := npm.store.Get(context.Background(), uidPartition(), string(oldPod.UID))
		if err == nil && found {
			rec, err := unmarshalUIDRecord(item.Payload)
			if err == nil {
				nominatingInfo = &framework.NominatingInfo{
					NominatingMode:    framework.ModeOverride,
					NominatedNodeName: rec.NodeName,
				}
			}
		}
	}

	npm.deleteUnlocked(oldPod)
	npm.addNominatedPodUnlocked(logger, newPodInfo, nominatingInfo)
}

// DeleteNominatedPodIfExists deletes <pod> from nominatedPods.
func (npm *nominator) DeleteNominatedPodIfExists(pod *v1.Pod) {
	npm.nLock.Lock()
	npm.deleteUnlocked(pod)
	npm.nLock.Unlock()
}

func (npm *nominator) deleteUnlocked(pod *v1.Pod) {
	item, found, err := npm.store.Get(context.Background(), uidPartition(), string(pod.UID))
	if err != nil || !found {
		return
	}

	rec, err := unmarshalUIDRecord(item.Payload)
	if err != nil {
		return
	}

	_ = npm.store.TransactWrite(context.Background(), []dbtypes.TransactWriteItem{
		npm.store.DeleteTx(uidPartition(), string(pod.UID)),
		npm.store.DeleteTx(nodePartition(rec.NodeName), string(pod.UID)),
	})
}

func (npm *nominator) nominatedPodsForNode(nodeName string) []podRef {
	npm.nLock.RLock()
	defer npm.nLock.RUnlock()
	items, err := npm.store.ListPartition(context.Background(), nodePartition(nodeName))
	if err != nil {
		return nil
	}

	out := make([]podRef, 0, len(items))
	for _, item := range items {
		ref, err := unmarshalPodRef(item.Payload)
		if err != nil {
			continue
		}
		out = append(out, *ref)
	}
	return out
}

// nominatedNodeName returns nominated node name of a Pod.
func nominatedNodeName(pod *v1.Pod) string {
	return pod.Status.NominatedNodeName
}

type podRef struct {
	name      string
	namespace string
	uid       types.UID
}

func podToRef(pod *v1.Pod) podRef {
	return podRef{
		name:      pod.Name,
		namespace: pod.Namespace,
		uid:       pod.UID,
	}
}

func (np podRef) toPod() *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      np.name,
			Namespace: np.namespace,
			UID:       np.uid,
		},
	}
}

type nominatedUIDRecord struct {
	NodeName string `json:"nodeName"`
	Ref      podRef `json:"ref"`
}

func uidPartition() string {
	return nominatorUIDPartitionPrefix
}

func nodePartition(nodeName string) string {
	return nominatorNodePartitionPrefix + nodeName
}

func marshalJSON(v any) ([]byte, error) {
	return json.Marshal(v)
}

func unmarshalUIDRecord(data []byte) (*nominatedUIDRecord, error) {
	var out nominatedUIDRecord
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func unmarshalPodRef(data []byte) (*podRef, error) {
	var out podRef
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
