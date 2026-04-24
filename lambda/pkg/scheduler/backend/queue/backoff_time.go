package queue

import (
	"time"

	"k8s.io/kubernetes/pkg/scheduler/framework"

	"lambda/pkg/scheduler/backend/awsstore"
)

func CalculateBackoffExpiration(
	pInfo *framework.QueuedPodInfo,
	initial time.Duration,
	max time.Duration,
) time.Time {
	if pInfo == nil || pInfo.Attempts == 0 {
		return time.Time{}
	}

	if !pInfo.BackoffExpiration.IsZero() {
		return pInfo.BackoffExpiration
	}

	duration := initial
	for i := 1; i < pInfo.Attempts; i++ {
		if duration > max-duration {
			duration = max
			break
		}
		duration += duration
	}

	return pInfo.Timestamp.Add(duration)
}

func NewBackoffTimeFunc(
	initial time.Duration,
	max time.Duration,
) awsstore.BackoffTimeFunc {
	return func(pInfo *framework.QueuedPodInfo) time.Time {
		return CalculateBackoffExpiration(pInfo, initial, max)
	}
}
