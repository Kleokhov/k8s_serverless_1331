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

package cache

import (
	"context"
	"fmt"
	"sync"
	"time"

	"lambda/pkg/scheduler/backend/awsstore"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/scheduler/framework"
)

func New(ctx context.Context, mapStore awsstore.DynamoMap) Cache {
	cache := newCache(ctx, mapStore)
	return cache
}

type cacheImpl struct {
	stop   <-chan struct{}
	ttl    time.Duration
	period time.Duration
	mu     sync.RWMutex

	store *awsstore.CacheStore
}

func newCache(ctx context.Context, mapStore awsstore.DynamoMap) *cacheImpl {
	return &cacheImpl{
		stop:  ctx.Done(),
		store: awsstore.NewCacheStore(mapStore),
	}
}

func (cache *cacheImpl) Dump() *Dump {
	cache.mu.RLock()
	defer cache.mu.RUnlock()

	ctx := context.Background()

	nodeRecs, _ := cache.store.ListNodes(ctx)
	nodes := make(map[string]*framework.NodeInfo, len(nodeRecs))
	for name, rec := range nodeRecs {
		nodes[name] = awsstore.RebuildNodeInfo(rec).Snapshot()
	}

	assumedKeys, _ := cache.store.ListAssumedPodKeys(ctx)

	return &Dump{
		Nodes:       nodes,
		AssumedPods: sets.New[string](assumedKeys...),
	}
}

func (cache *cacheImpl) UpdateSnapshot(_ klog.Logger) (map[string]*framework.NodeInfo, error) {
	cache.mu.RLock()
	defer cache.mu.RUnlock()

	nodeRecs, err := cache.store.ListNodes(context.Background())
	if err != nil {
		return nil, err
	}

	snapshot := make(map[string]*framework.NodeInfo, len(nodeRecs))
	for name, rec := range nodeRecs {
		nodeInfo := awsstore.RebuildNodeInfo(rec).Snapshot()
		if nodeInfo == nil || nodeInfo.Node() == nil {
			continue
		}
		snapshot[name] = nodeInfo
	}

	return snapshot, nil
}

func (cache *cacheImpl) GetNodeInfo(_ klog.Logger, nodeName string) (*framework.NodeInfo, bool, error) {
	cache.mu.RLock()
	defer cache.mu.RUnlock()

	rec, found, _, err := cache.store.GetNode(context.Background(), nodeName)
	if err != nil || !found {
		return nil, found, err
	}

	nodeInfo := awsstore.RebuildNodeInfo(rec).Snapshot()
	if nodeInfo == nil || nodeInfo.Node() == nil {
		return nil, false, nil
	}
	return nodeInfo, true, nil
}

// NodeCount returns the number of nodes in the cache.
func (cache *cacheImpl) NodeCount() int {
	cache.mu.RLock()
	defer cache.mu.RUnlock()

	metas, err := cache.store.ListNodeMeta(context.Background())
	if err != nil {
		return 0
	}

	count := 0
	for _, rec := range metas {
		if rec.Node != nil {
			count++
		}
	}
	return count
}

// PodCount returns the number of pods in the cache (including those from deleted nodes).
func (cache *cacheImpl) PodCount() (int, error) {
	cache.mu.RLock()
	defer cache.mu.RUnlock()

	ctx := context.Background()
	metas, err := cache.store.ListNodeMeta(ctx)
	if err != nil {
		return 0, err
	}
	count := 0
	for name := range metas {
		n, err := cache.store.CountNodePods(ctx, name)
		if err != nil {
			return 0, err
		}
		count += n
	}
	return count, nil
}

func (cache *cacheImpl) AssumePod(logger klog.Logger, pod *v1.Pod) error {
	key, err := framework.GetPodKey(pod)
	if err != nil {
		return err
	}

	cache.mu.Lock()
	defer cache.mu.Unlock()

	ctx := context.Background()

	if _, found, _, err := cache.store.GetPodState(ctx, key); err != nil {
		return err
	} else if found {
		return fmt.Errorf("pod %v(%v) is in the cache, so can't be assumed", key, klog.KObj(pod))
	}

	return cache.addPod(logger, pod, true)
}

func (cache *cacheImpl) FinishBinding(logger klog.Logger, pod *v1.Pod) error {
	return cache.finishBinding(logger, pod, time.Now())
}

// finishBinding exists to make tests deterministic by injecting now as an argument
func (cache *cacheImpl) finishBinding(logger klog.Logger, pod *v1.Pod, now time.Time) error {
	key, err := framework.GetPodKey(pod)
	if err != nil {
		return err
	}

	cache.mu.RLock()
	defer cache.mu.RUnlock()

	ctx := context.Background()
	currState, found, _, err := cache.store.GetPodState(ctx, key)
	if err != nil || !found {
		return err
	}

	assumed, err := cache.store.IsAssumedPod(ctx, key)
	if err != nil {
		return err
	}
	if !assumed {
		return nil
	}

	logger.V(5).Info("Finished binding for pod, can be expired", "podKey", key, "pod", klog.KObj(pod))

	if cache.ttl == 0 {
		currState.Deadline = nil
	} else {
		dl := now.Add(cache.ttl)
		currState.Deadline = &dl
	}
	currState.BindingFinished = true
	return cache.store.UpsertPodState(ctx, key, currState)
}

func (cache *cacheImpl) ForgetPod(logger klog.Logger, pod *v1.Pod) error {
	key, err := framework.GetPodKey(pod)
	if err != nil {
		return err
	}

	cache.mu.Lock()
	defer cache.mu.Unlock()

	ctx := context.Background()

	currState, found, _, err := cache.store.GetPodState(ctx, key)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("pod %v(%v) wasn't assumed so cannot be forgotten", key, klog.KObj(pod))
	}

	if currState.Pod.Spec.NodeName != pod.Spec.NodeName {
		return fmt.Errorf("pod %v(%v) was assumed on %v but assigned to %v", key, klog.KObj(pod), pod.Spec.NodeName, currState.Pod.Spec.NodeName)
	}

	assumed, err := cache.store.IsAssumedPod(ctx, key)
	if err != nil {
		return err
	}
	if !assumed {
		return fmt.Errorf("pod %v(%v) wasn't assumed so cannot be forgotten", key, klog.KObj(pod))
	}

	return cache.removePod(logger, pod)
}

// Assumes that lock is already acquired.
func (cache *cacheImpl) addPod(logger klog.Logger, pod *v1.Pod, assumePod bool) error {
	ctx := context.Background()

	key, err := framework.GetPodKey(pod)
	if err != nil {
		return err
	}

	rec, found, _, err := cache.store.GetNodeMeta(ctx, pod.Spec.NodeName)
	if err != nil {
		return err
	}
	if !found {
		rec = awsstore.NewNodeRecord()
	}
	rec.Generation++
	rec.UpdatedAt = time.Now()
	if err := cache.store.UpsertNodeMeta(ctx, pod.Spec.NodeName, rec); err != nil {
		return err
	}

	if err := cache.store.AddNodePod(ctx, pod.Spec.NodeName, pod); err != nil {
		return err
	}

	const assumedPodTTL = 2 * time.Minute
	var deadline *time.Time
	if assumePod {
		dl := time.Now().Add(assumedPodTTL)
		deadline = &dl
	}
	ps := &awsstore.PodStateRecord{
		Pod:             pod,
		Deadline:        deadline,
		BindingFinished: false,
	}
	if err := cache.store.UpsertPodState(ctx, key, ps); err != nil {
		return err
	}

	if assumePod {
		if err := cache.store.AddAssumedPod(ctx, key); err != nil {
			return err
		}
	}
	return nil
}

// Assumes that lock is already acquired.
func (cache *cacheImpl) updatePod(logger klog.Logger, oldPod, newPod *v1.Pod) error {
	if err := cache.removePod(logger, oldPod); err != nil {
		return err
	}
	return cache.addPod(logger, newPod, false)
}

// Assumes that lock is already acquired.
// Removes a pod from the cached node info. If the node information was already
// removed and there are no more pods left in the node, cleans up the node from
// the cache.
func (cache *cacheImpl) removePod(logger klog.Logger, pod *v1.Pod) error {
	ctx := context.Background()

	key, err := framework.GetPodKey(pod)
	if err != nil {
		return err
	}

	rec, found, _, err := cache.store.GetNodeMeta(ctx, pod.Spec.NodeName)
	if err != nil {
		return err
	}
	if found {
		if _, err := cache.store.RemoveNodePod(ctx, pod.Spec.NodeName, key); err != nil {
			return err
		}
		remaining, err := cache.store.CountNodePods(ctx, pod.Spec.NodeName)
		if err != nil {
			return err
		}
		if remaining == 0 && rec.Node == nil {
			if _, err := cache.store.DeleteNodeMeta(ctx, pod.Spec.NodeName); err != nil {
				return err
			}
		} else {
			rec.Generation++
			rec.UpdatedAt = time.Now()
			if err := cache.store.UpsertNodeMeta(ctx, pod.Spec.NodeName, rec); err != nil {
				return err
			}
		}
	}

	_, _ = cache.store.DeletePodState(ctx, key)
	_, _ = cache.store.DeleteAssumedPod(ctx, key)
	return nil
}

func (cache *cacheImpl) AddPod(logger klog.Logger, pod *v1.Pod) error {
	key, err := framework.GetPodKey(pod)
	if err != nil {
		return err
	}

	cache.mu.Lock()
	defer cache.mu.Unlock()

	ctx := context.Background()

	currState, found, _, err := cache.store.GetPodState(ctx, key)
	if err != nil {
		return err
	}

	if found {
		assumed, err := cache.store.IsAssumedPod(ctx, key)
		if err != nil {
			return err
		}

		if assumed {
			// The pod was assumed earlier; refresh it into fully added state.
			if currState.Pod.Spec.NodeName != pod.Spec.NodeName {
				logger.Info("Pod was added to a different node than it was assumed", "podKey",
					key, "pod", klog.KObj(pod), "assumedNode", klog.KRef("", currState.Pod.Spec.NodeName),
					"currentNode", klog.KRef("", pod.Spec.NodeName))
				return nil
			}

			if err := cache.updatePod(logger, currState.Pod, pod); err != nil {
				logger.Error(err, "Error occurred while updating pod")
				return err
			}
			return nil
		}

		return fmt.Errorf("pod %v(%v) was already in added state", key, klog.KObj(pod))
	}

	// Pod state missing, likely expired or not yet seen.
	if err := cache.addPod(logger, pod, false); err != nil {
		logger.Error(err, "Error occurred while adding pod")
		return err
	}
	return nil
}

func (cache *cacheImpl) UpdatePod(logger klog.Logger, oldPod, newPod *v1.Pod) error {
	key, err := framework.GetPodKey(oldPod)
	if err != nil {
		return err
	}

	cache.mu.Lock()
	defer cache.mu.Unlock()

	ctx := context.Background()

	currState, found, _, err := cache.store.GetPodState(ctx, key)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("pod %v(%v) is not added to scheduler cache, so cannot be updated", key, klog.KObj(oldPod))
	}

	assumed, err := cache.store.IsAssumedPod(ctx, key)
	if err != nil {
		return err
	}
	if assumed {
		return fmt.Errorf("assumed pod %v(%v) should not be updated", key, klog.KObj(oldPod))
	}

	if currState.Pod.Spec.NodeName != newPod.Spec.NodeName {
		logger.Error(nil, "Pod updated on a different node than previously added to", "podKey", key, "pod", klog.KObj(oldPod))
		return fmt.Errorf("pod %v(%v) updated to a different node", key, klog.KObj(oldPod))
	}

	return cache.updatePod(logger, oldPod, newPod)
}

func (cache *cacheImpl) RemovePod(logger klog.Logger, pod *v1.Pod) error {
	key, err := framework.GetPodKey(pod)
	if err != nil {
		return err
	}

	cache.mu.Lock()
	defer cache.mu.Unlock()

	ctx := context.Background()

	currState, found, _, err := cache.store.GetPodState(ctx, key)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("pod %v(%v) is not found in scheduler cache, so cannot be removed from it", key, klog.KObj(pod))
	}

	if currState.Pod.Spec.NodeName != pod.Spec.NodeName {
		logger.Error(nil, "Pod was added to a different node than expected", "podKey", key, "pod", klog.KObj(pod), "cachedNode", klog.KRef("", currState.Pod.Spec.NodeName), "requestedNode", klog.KRef("", pod.Spec.NodeName))
		if pod.Spec.NodeName != "" {
			return fmt.Errorf("pod %v(%v) remove node mismatch", key, klog.KObj(pod))
		}
	}

	return cache.removePod(logger, currState.Pod)
}

func (cache *cacheImpl) IsAssumedPod(pod *v1.Pod) (bool, error) {
	key, err := framework.GetPodKey(pod)
	if err != nil {
		return false, err
	}

	cache.mu.RLock()
	defer cache.mu.RUnlock()

	return cache.store.IsAssumedPod(context.Background(), key)
}

// GetPod might return a pod for which its node has already been deleted from
// the main cache. This is useful to properly process pod update events.
func (cache *cacheImpl) GetPod(pod *v1.Pod) (*v1.Pod, error) {
	key, err := framework.GetPodKey(pod)
	if err != nil {
		return nil, err
	}

	cache.mu.RLock()
	defer cache.mu.RUnlock()

	rec, found, _, err := cache.store.GetPodState(context.Background(), key)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("pod %v(%v) does not exist in scheduler cache", key, klog.KObj(pod))
	}

	return rec.Pod, nil
}

func (cache *cacheImpl) AddNode(logger klog.Logger, node *v1.Node) *framework.NodeInfo {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	ctx := context.Background()

	rec, found, _, err := cache.store.GetNodeMeta(ctx, node.Name)
	if err != nil {
		logger.Error(err, "Failed to get node from cache store", "node", klog.KObj(node))
		return nil
	}
	if !found {
		rec = awsstore.NewNodeRecord()
	}
	rec.Node = node
	rec.Generation++
	rec.UpdatedAt = time.Now()

	if err := cache.store.UpsertNodeMeta(ctx, node.Name, rec); err != nil {
		logger.Error(err, "Failed to upsert node metadata", "node", klog.KObj(node))
		return nil
	}

	pods, err := cache.store.ListNodePods(ctx, node.Name)
	if err != nil {
		logger.Error(err, "Failed to list pods on node", "node", klog.KObj(node))
		return nil
	}
	rec.Pods = pods
	return awsstore.RebuildNodeInfo(rec).Snapshot()
}

func (cache *cacheImpl) UpdateNode(logger klog.Logger, oldNode, newNode *v1.Node) *framework.NodeInfo {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	ctx := context.Background()

	rec, found, _, err := cache.store.GetNodeMeta(ctx, oldNode.Name)
	if err != nil {
		logger.Error(err, "Failed to get node from cache store", "node", klog.KObj(oldNode))
		return nil
	}
	if !found {
		rec = awsstore.NewNodeRecord()
	}
	rec.Node = newNode
	rec.Generation++
	rec.UpdatedAt = time.Now()

	if err := cache.store.UpsertNodeMeta(ctx, newNode.Name, rec); err != nil {
		logger.Error(err, "Failed to upsert node metadata", "node", klog.KObj(newNode))
		return nil
	}

	pods, err := cache.store.ListNodePods(ctx, newNode.Name)
	if err != nil {
		logger.Error(err, "Failed to list pods on node", "node", klog.KObj(newNode))
		return nil
	}
	rec.Pods = pods
	return awsstore.RebuildNodeInfo(rec).Snapshot()
}

// RemoveNode removes a node from the cache's tree.
// The node might still have pods because their deletion events didn't arrive
// yet. Those pods are considered removed from the cache, being the node tree
// the source of truth.
// However, we keep a ghost node with the list of pods until all pod deletion
// events have arrived. A ghost node is skipped from snapshots.
func (cache *cacheImpl) RemoveNode(logger klog.Logger, node *v1.Node) error {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	ctx := context.Background()

	rec, found, _, err := cache.store.GetNodeMeta(ctx, node.Name)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("node %v is not found", node.Name)
	}

	rec.Node = nil
	rec.Generation++
	rec.UpdatedAt = time.Now()

	podCount, err := cache.store.CountNodePods(ctx, node.Name)
	if err != nil {
		return err
	}
	if podCount == 0 {
		_, err = cache.store.DeleteNodeMeta(ctx, node.Name)
		return err
	}
	return cache.store.UpsertNodeMeta(ctx, node.Name, rec)
}
