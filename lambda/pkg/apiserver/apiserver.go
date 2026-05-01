package apiserver

import (
	"context"
	"log"
	"net"
	"net/http"
	"os"
	"sync"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/awslabs/aws-lambda-go-api-proxy/httpadapter"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apiserver/pkg/storage/storagebackend"
	"k8s.io/klog/v2"
	app "k8s.io/kubernetes/cmd/kube-apiserver/app"
	"k8s.io/kubernetes/cmd/kube-apiserver/app/options"
)

var lambdaDefaultDisabledStartupComponents = []string{
	// Generic startup/readiness wiring.
	"generic-apiserver-start-informers",
	"informer-sync-readyz",

	// Generic request management loops.
	"priority-and-fairness-config-consumer",
	"priority-and-fairness-filter",
	"max-in-flight-filter",
	"storage-object-count-tracker-hook",
	"priority-and-fairness-config-producer",
	"start-apiserver-admission-initializer",
	"start-service-ip-repair-controllers",
	"scheduling/bootstrap-system-priority-classes",

	// Control plane/bootstrap hooks.
	"bootstrap-controller",
	"start-kubernetes-service-cidr-controller",
	"start-system-namespaces-controller",
	"start-kube-apiserver-coordinated-leader-election-controller",
	"start-cluster-authentication-info-controller",
	"start-kube-apiserver-identity-lease-controller",
	"start-kube-apiserver-identity-lease-garbage-collector",
	"start-legacy-token-tracking-controller",
	"storage-readiness",

	// Aggregator/peer controllers.
	"start-kube-aggregator-informers",
	"apiservice-status-local-available-controller",
	"apiservice-status-remote-available-controller",
	"apiservice-registration-controller",
	"apiservice-discovery-controller",
	"apiservice-openapi-controller",
	"apiservice-openapiv3-controller",
	"kube-apiserver-autoregistration",
	"autoregister-completion",
	"peer-endpoint-reconciler-controller",
	"local-discovery-cache-sync",
	"peer-discovery-cache-sync",
	"mixed-version-proxy-handler",
}

// Run configures the Kubernetes apiserver for Lambda's handler-only model and
// starts the aws-lambda-go event loop.
func Run(ctx context.Context) {
	lambda.Start((&lazyProxy{baseCtx: ctx}).ProxyWithContext)
}

type lazyProxy struct {
	baseCtx context.Context
	mu      sync.Mutex
	adapter *httpadapter.HandlerAdapterV2
}

func (p *lazyProxy) ProxyWithContext(ctx context.Context, event events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	adapter, err := p.adapterFor(ctx)
	if err != nil {
		log.Printf("failed to build handler: %v", err)
		return events.APIGatewayV2HTTPResponse{
			StatusCode: 500,
			Headers: map[string]string{
				"Content-Type": "text/plain; charset=utf-8",
			},
			Body: "failed to build lambda apiserver handler\n",
		}, nil
	}
	return adapter.ProxyWithContext(ctx, event)
}

func (p *lazyProxy) adapterFor(ctx context.Context) (*httpadapter.HandlerAdapterV2, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.adapter != nil {
		return p.adapter, nil
	}

	buildCtx := p.baseCtx
	if buildCtx == nil {
		buildCtx = ctx
	}
	handler, err := BuildHandler(buildCtx)
	if err != nil {
		return nil, err
	}
	p.adapter = httpadapter.NewV2(handler)
	return p.adapter, nil
}

// BuildHandler constructs the full Kubernetes API http.Handler for one Lambda
// cold start. Warm invocations reuse the returned handler.
func BuildHandler(ctx context.Context) (http.Handler, error) {
	opts, err := completedOptions(ctx)
	if err != nil {
		return nil, err
	}
	return buildServerHandler(ctx, opts)
}

func completedOptions(ctx context.Context) (options.CompletedOptions, error) {
	s := options.NewServerRunOptions()

	// Hardcode key startup options for serverless mode.
	s.Authorization.Modes = []string{"AlwaysAllow"}
	s.Authentication.Anonymous.Allow = true
	// Handler-only mode does not run informer/bootstrap startup paths. Keep a
	// minimal admission chain so requests do not wait on informer sync.
	s.Admission.PluginNames = []string{"AlwaysAdmit"}

	dynamoRegion := getenvDefault("DYNAMO_REGION", "us-east-1")
	dynamoTable := getenvDefault("DYNAMO_TABLE", "dynamo")
	dynamoEndpoint := os.Getenv("DYNAMO_ENDPOINT")
	advertiseAddress := net.ParseIP(getenvDefault("APISERVER_ADVERTISE_ADDRESS", "127.0.0.1"))
	bindAddress := net.ParseIP(getenvDefault("APISERVER_BIND_ADDRESS", "127.0.0.1"))
	if advertiseAddress == nil {
		return options.CompletedOptions{}, errInvalidIP("APISERVER_ADVERTISE_ADDRESS")
	}
	if bindAddress == nil {
		return options.CompletedOptions{}, errInvalidIP("APISERVER_BIND_ADDRESS")
	}

	if os.Getenv("AWS_REGION") == "" {
		_ = os.Setenv("AWS_REGION", dynamoRegion)
	}
	if os.Getenv("AWS_DEFAULT_REGION") == "" {
		_ = os.Setenv("AWS_DEFAULT_REGION", dynamoRegion)
	}
	if dynamoEndpoint == "" && !hasAWSCredentialSource() {
		klog.InfoS("No explicit AWS credential source detected; DynamoDB auth may fail", "hint", "set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY, AWS_PROFILE with mounted /root/.aws, or run with Lambda execution role")
	}

	s.Etcd.StorageConfig.Transport.ServerList = []string{"https://127.0.0.1:2379"}
	s.Etcd.StorageConfig.Type = storagebackend.StorageTypeDynamo
	s.Etcd.EnableWatchCache = false
	s.GenericServerRunOptions.AdvertiseAddress = advertiseAddress
	s.SecureServing.BindAddress = bindAddress
	// Lambda's filesystem is read-only outside /tmp. The secure listener cert is
	// not used in handler-only mode, so generate it in memory.
	s.SecureServing.ServerCert.CertDirectory = ""
	s.SecureServing.ServerCert.PairName = ""
	s.ServiceClusterIPRanges = getenvDefault("SERVICE_CLUSTER_IP_RANGE", "10.96.0.0/12")
	s.CustomStorage.DynamoRegion = dynamoRegion
	s.CustomStorage.DynamoTable = dynamoTable
	s.CustomStorage.DynamoEndpoint = dynamoEndpoint
	s.Authentication.TokenFile.TokenFile = "/etc/kubernetes/auth/tokens.csv"
	s.Authentication.ServiceAccounts.Issuers = []string{"https://kubernetes.default.svc.cluster.local"}
	s.Authentication.ServiceAccounts.KeyFiles = []string{"/etc/kubernetes/pki/sa.pub"}
	s.ServiceAccountSigningKeyFile = "/etc/kubernetes/pki/sa.key"

	completedOptions, err := s.Complete(ctx)
	if err != nil {
		return options.CompletedOptions{}, err
	}

	// Defensively set Dynamo fields on the completed options consumed by the
	// storage factory to avoid empty-region failures during initialization.
	completedOptions.Etcd.StorageConfig.Type = storagebackend.StorageTypeDynamo
	completedOptions.Etcd.StorageConfig.Dynamo.Region = dynamoRegion
	completedOptions.Etcd.StorageConfig.Dynamo.TableName = dynamoTable
	completedOptions.Etcd.StorageConfig.Dynamo.Endpoint = dynamoEndpoint
	completedOptions.Etcd.EnableWatchCache = false
	completedOptions.Etcd.SkipHealthEndpoints = true
	completedOptions.CustomStorage.DynamoRegion = dynamoRegion
	completedOptions.CustomStorage.DynamoTable = dynamoTable
	completedOptions.CustomStorage.DynamoEndpoint = dynamoEndpoint
	completedOptions.DisableStartupComponents = append([]string{}, lambdaDefaultDisabledStartupComponents...)
	klog.InfoS("Configured disabled startup components", "count", len(completedOptions.DisableStartupComponents), "components", completedOptions.DisableStartupComponents)

	if errs := completedOptions.Validate(); len(errs) != 0 {
		return options.CompletedOptions{}, utilerrors.NewAggregate(errs)
	}
	return completedOptions, nil
}

func buildServerHandler(ctx context.Context, opts options.CompletedOptions) (http.Handler, error) {
	klog.InfoS("Golang settings", "GOGC", os.Getenv("GOGC"), "GOMAXPROCS", os.Getenv("GOMAXPROCS"), "GOTRACEBACK", os.Getenv("GOTRACEBACK"))

	config, err := app.NewConfig(opts)
	if err != nil {
		return nil, err
	}
	completed, err := config.Complete()
	if err != nil {
		return nil, err
	}
	server, err := app.CreateServerChain(completed)
	if err != nil {
		return nil, err
	}

	prepared, err := server.PrepareRun()
	if err != nil {
		return nil, err
	}

	// Do not start post-start hooks. They assume a long-lived secure listener
	// and make loopback calls to :6443, which Lambda handler-only mode lacks.
	return prepared.APIAggregator.GenericAPIServer.Handler, nil
}

func getenvDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func errInvalidIP(key string) error {
	return &net.ParseError{Type: "IP address", Text: os.Getenv(key)}
}

func hasAWSCredentialSource() bool {
	for _, key := range []string{
		"AWS_ACCESS_KEY_ID",
		"AWS_PROFILE",
		"AWS_WEB_IDENTITY_TOKEN_FILE",
		"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
		"AWS_CONTAINER_CREDENTIALS_FULL_URI",
	} {
		if os.Getenv(key) != "" {
			return true
		}
	}

	if _, err := os.Stat("/root/.aws/credentials"); err == nil {
		return true
	}
	return false
}
