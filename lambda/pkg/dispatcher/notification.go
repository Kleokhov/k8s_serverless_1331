package dispatcher

import (
	"context"
	"sort"
	"strings"
	"time"
)

type queueNotification struct {
	body     string
	dedupKey string
	delay    time.Duration
}

type notificationBatch struct {
	items map[string]queueNotification
}

func newNotificationBatch() *notificationBatch {
	return &notificationBatch{items: make(map[string]queueNotification)}
}

func (b *notificationBatch) add(body, dedupKey string, delay time.Duration) {
	body = strings.TrimSpace(body)
	if body == "" {
		return
	}
	if delay < 0 {
		delay = 0
	}
	b.items[body] = queueNotification{
		body:     body,
		dedupKey: strings.TrimSpace(dedupKey),
		delay:    delay,
	}
}

func sendNotificationBatch(ctx context.Context, q DedupQueue, batch *notificationBatch) (int, error) {
	if q == nil || batch == nil || len(batch.items) == 0 {
		return 0, nil
	}

	keys := make([]string, 0, len(batch.items))
	for key := range batch.items {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		item := batch.items[key]
		if err := q.EnqueueAfterWithDeduplicationID(ctx, item.body, item.dedupKey, item.delay); err != nil {
			return 0, err
		}
	}

	return len(keys), nil
}

type controllerNotifications struct {
	job       *notificationBatch
	jobOrphan *notificationBatch
	ttl       *notificationBatch
	namespace *notificationBatch
}

func newControllerNotifications() *controllerNotifications {
	return &controllerNotifications{
		job:       newNotificationBatch(),
		jobOrphan: newNotificationBatch(),
		ttl:       newNotificationBatch(),
		namespace: newNotificationBatch(),
	}
}
