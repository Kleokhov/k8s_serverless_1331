package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"

	dynamostore "k8s.io/apiserver/pkg/storage/dynamo"
)

var resourceSuffixes = []string{
	"",
	"core-events",
	"core-resourcequotas",
	"core-secrets",
	"core-configmaps",
	"core-namespaces",
	"core-serviceaccounts",
	"core-podtemplates",
	"core-limitranges",
	"core-persistentvolumes",
	"core-persistentvolumeclaims",
	"core-endpoints",
	"core-nodes",
	"core-pods",
	"core-services",
	"core-replicationcontrollers",
	"autoscaling-horizontalpodautoscalers",
	"batch-jobs",
	"batch-cronjobs",
	"certificates_k8s_io-certificatesigningrequests",
	"coordination_k8s_io-leases",
	"discovery_k8s_io-endpointslices",
	"networking_k8s_io-networkpolicies",
	"networking_k8s_io-ingresses",
	"networking_k8s_io-ingressclasses",
	"networking_k8s_io-ipaddresses",
	"networking_k8s_io-servicecidrs",
	"node_k8s_io-runtimeclasses",
	"policy-poddisruptionbudgets",
	"rbac_authorization_k8s_io-roles",
	"rbac_authorization_k8s_io-rolebindings",
	"rbac_authorization_k8s_io-clusterroles",
	"rbac_authorization_k8s_io-clusterrolebindings",
	"scheduling_k8s_io-priorityclasses",
	"storage_k8s_io-storageclasses",
	"storage_k8s_io-volumeattachments",
	"storage_k8s_io-csinodes",
	"storage_k8s_io-csidrivers",
	"storage_k8s_io-csistoragecapacities",
	"flowcontrol_apiserver_k8s_io-flowschemas",
	"flowcontrol_apiserver_k8s_io-prioritylevelconfigurations",
	"apps-deployments",
	"apps-statefulsets",
	"apps-daemonsets",
	"apps-replicasets",
	"apps-controllerrevisions",
	"admissionregistration_k8s_io-validatingwebhookconfigurations",
	"admissionregistration_k8s_io-mutatingwebhookconfigurations",
	"admissionregistration_k8s_io-validatingadmissionpolicies",
	"admissionregistration_k8s_io-validatingadmissionpolicybindings",
}

func buildTableNames(base string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(resourceSuffixes))

	for _, suffix := range resourceSuffixes {
		name := base
		if suffix != "" {
			name = base + "-" + suffix
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out
}

func newDynamoClient(ctx context.Context, region, endpoint string) (*dynamodb.Client, error) {
	loadOpts := []func(*config.LoadOptions) error{
		config.WithRegion(region),
	}

	// Only use dummy creds for local endpoints.
	if endpoint != "" {
		loadOpts = append(loadOpts,
			config.WithCredentialsProvider(
				credentials.NewStaticCredentialsProvider("dummy", "dummy", ""),
			),
		)
	}

	awsCfg, err := config.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}

	client := dynamodb.NewFromConfig(awsCfg, func(o *dynamodb.Options) {
		if endpoint != "" {
			o.BaseEndpoint = aws.String(endpoint)
		}
	})

	return client, nil
}

func main() {
	var region string
	var endpoint string
	var tableBase string

	flag.StringVar(&region, "region", "us-east-1", "AWS region")
	flag.StringVar(&endpoint, "endpoint", "", "optional DynamoDB endpoint (for local testing)")
	flag.StringVar(&tableBase, "table", "dynamo", "base DynamoDB table name prefix")
	flag.Parse()

	ctx := context.Background()

	ddb, err := newDynamoClient(ctx, region, endpoint)
	if err != nil {
		log.Fatalf("failed to create dynamodb client: %v", err)
	}

	tables := buildTableNames(tableBase)
	for _, table := range tables {
		tableCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		err := dynamostore.EnsureTableBootstrap(tableCtx, ddb, table)
		cancel()
		if err != nil {
			log.Fatalf("failed bootstrapping table %q: %v", table, err)
		}
		log.Printf("ensured table: %s", table)
	}

	log.Printf("done: initialized %d DynamoDB tables", len(tables))
}
