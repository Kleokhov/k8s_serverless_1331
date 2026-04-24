package queue

import (
	"context"
	"sort"
	"testing"
	"time"

	dbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/scheduler/framework"
	schedmetrics "k8s.io/kubernetes/pkg/scheduler/metrics"
	clocktesting "k8s.io/utils/clock/testing"

	"lambda/pkg/scheduler/backend/awsstore"
)

func init() {
	schedmetrics.Register()
}

func TestFlushBackoffQCompletedRestoresPodOnActiveWriteFailure(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	pInfo := testQueuedPodInfo(t, "backoff-pod", now.Add(-time.Minute))

	activeQ := &fakeActiveQueue{failAdds: 1}
	backoffQ := &fakeBackoffQueue{
		ready: []*framework.QueuedPodInfo{pInfo},
	}
	pq := &PriorityQueue{
		clock:    clocktesting.NewFakeClock(now),
		stop:     make(chan struct{}),
		activeQ:  activeQ,
		backoffQ: backoffQ,
	}

	moved := pq.FlushBackoffQCompletedOnce(testLogger())
	if moved != 0 {
		t.Fatalf("expected no activations, got %d", moved)
	}
	if activeQ.len() != 0 {
		t.Fatalf("expected active queue to remain empty, got %d items", activeQ.len())
	}
	if !backoffQ.has(pInfo) {
		t.Fatalf("expected pod to be restored to backoff queue")
	}
}

func TestFlushUnschedulablePodsLeftoverSkipsStaleVersion(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	oldPInfo := testQueuedPodInfo(t, "stale-pod", now.Add(-10*time.Minute))
	currentPInfo := testQueuedPodInfo(t, "stale-pod", now)

	store := newFakeDynamoMap()
	seedUnschedulable(t, store, currentPInfo, 2)
	store.listPartitionFn = func(ctx context.Context, pk string) ([]*awsstore.MapItem, error) {
		if pk != unschedulablePartitionKey {
			return nil, nil
		}
		return []*awsstore.MapItem{mustMapItem(t, pk, fullName(oldPInfo.Pod), oldPInfo, 1)}, nil
	}

	activeQ := &fakeActiveQueue{}
	backoffQ := &fakeBackoffQueue{}
	pq := &PriorityQueue{
		clock:                             clocktesting.NewFakeClock(now),
		stop:                              make(chan struct{}),
		podMaxInUnschedulablePodsDuration: 5 * time.Minute,
		activeQ:                           activeQ,
		backoffQ:                          backoffQ,
		unschedulablePods:                 newUnschedulablePods(store, nil, nil),
	}

	moved := pq.FlushUnschedulablePodsLeftoverOnce(testLogger())
	if moved != 0 {
		t.Fatalf("expected no moved pods, got %d", moved)
	}
	if activeQ.len() != 0 {
		t.Fatalf("expected active queue to remain empty, got %d items", activeQ.len())
	}
	if backoffQ.len() != 0 {
		t.Fatalf("expected backoff queue to remain empty, got %d items", backoffQ.len())
	}
	got := pq.unschedulablePods.get(currentPInfo.Pod)
	if got == nil {
		t.Fatalf("expected current unschedulable pod to remain present")
	}
	if !got.Timestamp.Equal(currentPInfo.Timestamp) {
		t.Fatalf("expected unschedulable timestamp %v, got %v", currentPInfo.Timestamp, got.Timestamp)
	}
}

func TestFlushUnschedulablePodsLeftoverRestoresPodOnActiveWriteFailure(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	pInfo := testQueuedPodInfo(t, "retry-pod", now.Add(-10*time.Minute))

	store := newFakeDynamoMap()
	seedUnschedulable(t, store, pInfo, 1)

	activeQ := &fakeActiveQueue{failAdds: 1}
	backoffQ := &fakeBackoffQueue{}
	pq := &PriorityQueue{
		clock:                             clocktesting.NewFakeClock(now),
		stop:                              make(chan struct{}),
		podMaxInUnschedulablePodsDuration: 5 * time.Minute,
		activeQ:                           activeQ,
		backoffQ:                          backoffQ,
		unschedulablePods:                 newUnschedulablePods(store, nil, nil),
	}

	moved := pq.FlushUnschedulablePodsLeftoverOnce(testLogger())
	if moved != 0 {
		t.Fatalf("expected no moved pods, got %d", moved)
	}
	if activeQ.len() != 0 {
		t.Fatalf("expected active queue to remain empty, got %d items", activeQ.len())
	}
	if pq.unschedulablePods.get(pInfo.Pod) == nil {
		t.Fatalf("expected pod to be restored to unschedulable queue")
	}
}

func TestFlushUnschedulablePodsLeftoverMovesToBackoffWhenStillBackingOff(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	pInfo := testQueuedPodInfo(t, "backing-off-pod", now.Add(-10*time.Minute))

	store := newFakeDynamoMap()
	seedUnschedulable(t, store, pInfo, 1)

	activeQ := &fakeActiveQueue{}
	backoffQ := &fakeBackoffQueue{
		backingOff: map[string]bool{podInfoKeyFunc(pInfo): true},
	}
	pq := &PriorityQueue{
		clock:                             clocktesting.NewFakeClock(now),
		stop:                              make(chan struct{}),
		podMaxInUnschedulablePodsDuration: 5 * time.Minute,
		activeQ:                           activeQ,
		backoffQ:                          backoffQ,
		unschedulablePods:                 newUnschedulablePods(store, nil, nil),
	}

	moved := pq.FlushUnschedulablePodsLeftoverOnce(testLogger())
	if moved != 1 {
		t.Fatalf("expected one moved pod, got %d", moved)
	}
	if pq.unschedulablePods.get(pInfo.Pod) != nil {
		t.Fatalf("expected pod to leave unschedulable queue")
	}
	if !backoffQ.has(pInfo) {
		t.Fatalf("expected pod to move to backoff queue")
	}
	if activeQ.len() != 0 {
		t.Fatalf("expected active queue to remain empty, got %d items", activeQ.len())
	}
}

type fakeActiveQueue struct {
	items      map[string]*framework.QueuedPodInfo
	failAdds   int
	broadcasts int
}

func (q *fakeActiveQueue) underLock(fn func(unlockedActiveQ unlockedActiveQueuer)) {
	fn(q)
}

func (q *fakeActiveQueue) underRLock(fn func(unlockedActiveQ unlockedActiveQueueReader)) {
	fn(q)
}

func (q *fakeActiveQueue) add(pInfo *framework.QueuedPodInfo, event string) bool {
	if q.failAdds > 0 {
		q.failAdds--
		return false
	}
	if q.items == nil {
		q.items = map[string]*framework.QueuedPodInfo{}
	}
	q.items[podInfoKeyFunc(pInfo)] = pInfo
	return true
}

func (q *fakeActiveQueue) get(pInfo *framework.QueuedPodInfo) (*framework.QueuedPodInfo, bool) {
	if q.items == nil {
		return nil, false
	}
	out, ok := q.items[podInfoKeyFunc(pInfo)]
	return out, ok
}

func (q *fakeActiveQueue) has(pInfo *framework.QueuedPodInfo) bool {
	_, ok := q.get(pInfo)
	return ok
}

func (q *fakeActiveQueue) update(newPod *v1.Pod, oldPodInfo *framework.QueuedPodInfo) *framework.QueuedPodInfo {
	return nil
}

func (q *fakeActiveQueue) delete(pInfo *framework.QueuedPodInfo) error {
	if q.items != nil {
		delete(q.items, podInfoKeyFunc(pInfo))
	}
	return nil
}

func (q *fakeActiveQueue) pop(logger klog.Logger) (*framework.QueuedPodInfo, error) {
	return nil, nil
}

func (q *fakeActiveQueue) list() []*v1.Pod {
	out := make([]*v1.Pod, 0, len(q.items))
	for _, pInfo := range q.items {
		out = append(out, pInfo.Pod)
	}
	return out
}

func (q *fakeActiveQueue) len() int {
	return len(q.items)
}

func (q *fakeActiveQueue) schedulingCycle() int64 {
	return 0
}

func (q *fakeActiveQueue) done(pod types.UID) {}

func (q *fakeActiveQueue) close() {}

func (q *fakeActiveQueue) broadcast() {
	q.broadcasts++
}

type fakeBackoffQueue struct {
	items      map[string]*framework.QueuedPodInfo
	ready      []*framework.QueuedPodInfo
	backingOff map[string]bool
	failAdds   int
}

func (q *fakeBackoffQueue) isPodBackingoff(pInfo *framework.QueuedPodInfo) bool {
	return q.backingOff[podInfoKeyFunc(pInfo)]
}

func (q *fakeBackoffQueue) popAllBackoffCompleted(logger klog.Logger) []*framework.QueuedPodInfo {
	out := append([]*framework.QueuedPodInfo(nil), q.ready...)
	q.ready = nil
	return out
}

func (q *fakeBackoffQueue) podInitialBackoffDuration() time.Duration {
	return 0
}

func (q *fakeBackoffQueue) podMaxBackoffDuration() time.Duration {
	return 0
}

func (q *fakeBackoffQueue) waitUntilAlignedWithOrderingWindow(f func(), stopCh <-chan struct{}) {}

func (q *fakeBackoffQueue) add(logger klog.Logger, pInfo *framework.QueuedPodInfo, event string) bool {
	if q.failAdds > 0 {
		q.failAdds--
		return false
	}
	if q.items == nil {
		q.items = map[string]*framework.QueuedPodInfo{}
	}
	q.items[podInfoKeyFunc(pInfo)] = pInfo
	return true
}

func (q *fakeBackoffQueue) update(newPod *v1.Pod, oldPodInfo *framework.QueuedPodInfo) *framework.QueuedPodInfo {
	return nil
}

func (q *fakeBackoffQueue) delete(pInfo *framework.QueuedPodInfo) bool {
	if q.items == nil {
		return false
	}
	key := podInfoKeyFunc(pInfo)
	if _, ok := q.items[key]; !ok {
		return false
	}
	delete(q.items, key)
	return true
}

func (q *fakeBackoffQueue) get(pInfoLookup *framework.QueuedPodInfo) (*framework.QueuedPodInfo, bool) {
	if q.items == nil {
		return nil, false
	}
	out, ok := q.items[podInfoKeyFunc(pInfoLookup)]
	return out, ok
}

func (q *fakeBackoffQueue) has(pInfo *framework.QueuedPodInfo) bool {
	_, ok := q.get(pInfo)
	return ok
}

func (q *fakeBackoffQueue) list() []*v1.Pod {
	out := make([]*v1.Pod, 0, len(q.items))
	for _, pInfo := range q.items {
		out = append(out, pInfo.Pod)
	}
	return out
}

func (q *fakeBackoffQueue) len() int {
	return len(q.items)
}

type fakeDynamoMap struct {
	items           map[string]*awsstore.MapItem
	listPartitionFn func(ctx context.Context, pk string) ([]*awsstore.MapItem, error)
}

func newFakeDynamoMap() *fakeDynamoMap {
	return &fakeDynamoMap{
		items: map[string]*awsstore.MapItem{},
	}
}

func (m *fakeDynamoMap) Get(ctx context.Context, pk, sk string) (*awsstore.MapItem, bool, error) {
	item, ok := m.items[m.key(pk, sk)]
	if !ok {
		return nil, false, nil
	}
	return cloneMapItem(item), true, nil
}

func (m *fakeDynamoMap) Upsert(ctx context.Context, pk, sk string, payload []byte, extra map[string]dbtypes.AttributeValue) error {
	key := m.key(pk, sk)
	version := int64(1)
	if cur, ok := m.items[key]; ok {
		version = cur.Version + 1
	}
	m.items[key] = &awsstore.MapItem{
		PK:      pk,
		SK:      sk,
		Payload: append([]byte(nil), payload...),
		Version: version,
	}
	return nil
}

func (m *fakeDynamoMap) Delete(ctx context.Context, pk, sk string) (bool, error) {
	key := m.key(pk, sk)
	if _, ok := m.items[key]; !ok {
		return false, nil
	}
	delete(m.items, key)
	return true, nil
}

func (m *fakeDynamoMap) DeleteIfVersion(ctx context.Context, pk, sk string, expectedVersion int64) (bool, error) {
	key := m.key(pk, sk)
	cur, ok := m.items[key]
	if !ok || cur.Version != expectedVersion {
		return false, nil
	}
	delete(m.items, key)
	return true, nil
}

func (m *fakeDynamoMap) ListPartition(ctx context.Context, pk string) ([]*awsstore.MapItem, error) {
	if m.listPartitionFn != nil {
		return m.listPartitionFn(ctx, pk)
	}

	out := make([]*awsstore.MapItem, 0)
	for _, item := range m.items {
		if item.PK == pk {
			out = append(out, cloneMapItem(item))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].SK < out[j].SK
	})
	return out, nil
}

func (m *fakeDynamoMap) CountPartition(ctx context.Context, pk string) (int, error) {
	count := 0
	for _, item := range m.items {
		if item.PK == pk {
			count++
		}
	}
	return count, nil
}

func (m *fakeDynamoMap) PutTx(pk, sk string, payload []byte, extra map[string]dbtypes.AttributeValue) dbtypes.TransactWriteItem {
	return dbtypes.TransactWriteItem{}
}

func (m *fakeDynamoMap) DeleteTx(pk, sk string) dbtypes.TransactWriteItem {
	return dbtypes.TransactWriteItem{}
}

func (m *fakeDynamoMap) TransactWrite(ctx context.Context, items []dbtypes.TransactWriteItem) error {
	return nil
}

func (m *fakeDynamoMap) key(pk, sk string) string {
	return pk + "\x00" + sk
}

func cloneMapItem(item *awsstore.MapItem) *awsstore.MapItem {
	if item == nil {
		return nil
	}
	return &awsstore.MapItem{
		PK:      item.PK,
		SK:      item.SK,
		Payload: append([]byte(nil), item.Payload...),
		Version: item.Version,
	}
}

func testQueuedPodInfo(t *testing.T, name string, ts time.Time) *framework.QueuedPodInfo {
	t.Helper()

	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
			UID:       types.UID(name),
		},
	}
	podInfo, err := framework.NewPodInfo(pod)
	if err != nil {
		t.Fatalf("build pod info: %v", err)
	}

	return &framework.QueuedPodInfo{
		PodInfo:              podInfo,
		Timestamp:            ts,
		UnschedulablePlugins: sets.New[string](),
		PendingPlugins:       sets.New[string](),
	}
}

func seedUnschedulable(t *testing.T, store *fakeDynamoMap, pInfo *framework.QueuedPodInfo, version int64) {
	t.Helper()
	store.items[store.key(unschedulablePartitionKey, fullName(pInfo.Pod))] = mustMapItem(
		t,
		unschedulablePartitionKey,
		fullName(pInfo.Pod),
		pInfo,
		version,
	)
}

func mustMapItem(t *testing.T, pk, sk string, pInfo *framework.QueuedPodInfo, version int64) *awsstore.MapItem {
	t.Helper()
	payload, err := awsstore.MarshalQueuedPodInfo(pInfo)
	if err != nil {
		t.Fatalf("marshal queued pod info: %v", err)
	}
	return &awsstore.MapItem{
		PK:      pk,
		SK:      sk,
		Payload: payload,
		Version: version,
	}
}

func fullName(pod *v1.Pod) string {
	return pod.Name + "_" + pod.Namespace
}

func testLogger() klog.Logger {
	return klog.FromContext(context.Background())
}
