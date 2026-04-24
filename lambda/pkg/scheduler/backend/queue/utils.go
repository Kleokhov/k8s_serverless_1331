package queue

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"k8s.io/kubernetes/pkg/scheduler/metrics"

	"lambda/pkg/scheduler/backend/awsstore"
)

type initializedPriorityQueueParts struct {
	activeQ           *awsstore.ActiveQueueAWS
	backoffQ          *awsstore.BackoffQueuesAWS
	nominator         *nominator
	unschedulablePods *UnschedulablePods
}

func initializePriorityQueueParts(
	ctx context.Context,
	opts *priorityQueueOptions,
) (*initializedPriorityQueueParts, error) {
	metrics.Register()

	out := &initializedPriorityQueueParts{
		activeQ:           opts.awsActiveQ,
		backoffQ:          opts.awsBackoffQ,
		nominator:         opts.nominator,
		unschedulablePods: opts.unschedulablePods,
	}

	needClient := opts.createActiveQueue || opts.createBackoffQueues || opts.createNominator || opts.createUnschedulablePods
	var ddbClient *dynamodb.Client

	if needClient {
		if opts.awsCfg == nil {
			return nil, fmt.Errorf("aws config is required when creating dynamo-backed queue parts")
		}
		ddbClient = dynamodb.NewFromConfig(*opts.awsCfg, opts.ddbOpts...)
	}

	// Active queue gets its own table.
	if out.activeQ == nil && opts.createActiveQueue {
		activeEnv, err := awsstore.NewDynamoQueueEnvFromClient(ctx, ddbClient, opts.activeTableName)
		if err != nil {
			return nil, fmt.Errorf("init active queue env: %w", err)
		}
		activeQ, err := awsstore.NewActiveQueueFromEnv(activeEnv)
		if err != nil {
			return nil, fmt.Errorf("init active queue: %w", err)
		}
		out.activeQ = activeQ
	}

	// Backoff queues share one table.
	if out.backoffQ == nil && opts.createBackoffQueues {
		if opts.getBackoffTime == nil {
			return nil, fmt.Errorf("getBackoffTime is required when creating backoff queues")
		}
		backoffEnv, err := awsstore.NewDynamoQueueEnvFromClient(ctx, ddbClient, opts.backoffTableName)
		if err != nil {
			return nil, fmt.Errorf("init backoff queue env: %w", err)
		}
		backoffQ, err := awsstore.NewBackoffQueuesFromEnv(backoffEnv, opts.getBackoffTime)
		if err != nil {
			return nil, fmt.Errorf("init backoff queues: %w", err)
		}
		out.backoffQ = backoffQ
	}

	// Nominator and unschedulable pods share one map table, but are created independently.
	if (out.nominator == nil && opts.createNominator) || (out.unschedulablePods == nil && opts.createUnschedulablePods) {
		if opts.miscMapTableName == "" {
			return nil, fmt.Errorf("misc map table name is required when creating nominator or unschedulable pods")
		}

		mapEnv, err := awsstore.NewDynamoMapEnvFromClient(ctx, ddbClient, opts.miscMapTableName)
		if err != nil {
			return nil, fmt.Errorf("init map env: %w", err)
		}
		mapStore := awsstore.NewDynamoMapStore(mapEnv)

		if out.nominator == nil && opts.createNominator {
			out.nominator = newPodNominator(opts.kubeClient, mapStore)
		}
		if out.unschedulablePods == nil && opts.createUnschedulablePods {
			out.unschedulablePods = newUnschedulablePods(
				mapStore,
				metrics.NewUnschedulablePodsRecorder(),
				metrics.NewGatedPodsRecorder(),
			)
		}
	}

	return out, nil
}

func buildPriorityQueue(
	options priorityQueueOptions,
	parts *initializedPriorityQueueParts,
) *PriorityQueue {
	pq := &PriorityQueue{
		clock:                             options.clock,
		stop:                              make(chan struct{}),
		podMaxInUnschedulablePodsDuration: options.podMaxInUnschedulablePodsDuration,
		moveRequestCycle:                  -1,
	}

	if parts.activeQ != nil {
		pq.activeQ = newActiveQueue(parts.activeQ)
	}
	if parts.backoffQ != nil {
		pq.backoffQ = newBackoffQueue(
			options.clock,
			options.podInitialBackoffDuration,
			options.podMaxBackoffDuration,
			parts.backoffQ,
		)
	}
	pq.unschedulablePods = parts.unschedulablePods
	pq.nominator = parts.nominator

	return pq
}

func WithAWSConfig(cfg aws.Config, ddbOpts ...func(*dynamodb.Options)) Option {
	return func(o *priorityQueueOptions) {
		o.awsCfg = &cfg
		o.ddbOpts = ddbOpts
	}
}

func WithCreateActiveQueue(tableName string) Option {
	return func(o *priorityQueueOptions) {
		o.createActiveQueue = true
		o.activeTableName = tableName
	}
}

func WithCreateBackoffQueues(tableName string, getBackoffTime awsstore.BackoffTimeFunc) Option {
	return func(o *priorityQueueOptions) {
		o.createBackoffQueues = true
		o.backoffTableName = tableName
		o.getBackoffTime = getBackoffTime
	}
}

func WithMiscMapTable(tableName string) Option {
	return func(o *priorityQueueOptions) {
		o.miscMapTableName = tableName
	}
}

func WithCreateNominator() Option {
	return func(o *priorityQueueOptions) {
		o.createNominator = true
	}
}

func WithCreateUnschedulablePods() Option {
	return func(o *priorityQueueOptions) {
		o.createUnschedulablePods = true
	}
}
