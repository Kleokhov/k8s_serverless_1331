package queue

import (
	"context"
	"fmt"
)

func NewBackoffFlushQueue(
	ctx context.Context,
	opts ...Option,
) (*PriorityQueue, error) {
	options := defaultPriorityQueueOptions
	for _, opt := range opts {
		opt(&options)
	}

	parts, err := initializePriorityQueueParts(ctx, &options)
	if err != nil {
		return nil, err
	}
	if parts.activeQ == nil {
		return nil, fmt.Errorf("active queue is not configured")
	}
	if parts.backoffQ == nil {
		return nil, fmt.Errorf("backoff queues are not configured")
	}

	return buildPriorityQueue(options, parts), nil
}

func NewUnschedulableFlushQueue(
	ctx context.Context,
	opts ...Option,
) (*PriorityQueue, error) {
	options := defaultPriorityQueueOptions
	for _, opt := range opts {
		opt(&options)
	}

	parts, err := initializePriorityQueueParts(ctx, &options)
	if err != nil {
		return nil, err
	}
	if parts.activeQ == nil {
		return nil, fmt.Errorf("active queue is not configured")
	}
	if parts.backoffQ == nil {
		return nil, fmt.Errorf("backoff queues are not configured")
	}
	if parts.unschedulablePods == nil {
		return nil, fmt.Errorf("unschedulable pods are not configured")
	}

	return buildPriorityQueue(options, parts), nil
}
