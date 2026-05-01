package kubeconfig

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// defaultKubeAPIQPS / defaultKubeAPIBurst override client-go's 5/10 defaults
// so the no-watch Lambda components don't throttle their own per-reconcile
// API traffic. Override at runtime via KUBE_API_QPS / KUBE_API_BURST.
const (
	defaultKubeAPIQPS   float32 = 200
	defaultKubeAPIBurst int     = 400
)

// Load returns an out-of-cluster kubeconfig when one is explicitly provided
// and otherwise falls back to the normal in-cluster service account config.
func Load() (*rest.Config, error) {
	if path := strings.TrimSpace(os.Getenv("KUBECONFIG_PATH")); path != "" {
		cfg, err := clientcmd.BuildConfigFromFlags("", path)
		if err != nil {
			return nil, fmt.Errorf("build kubeconfig from KUBECONFIG_PATH=%q: %w", path, err)
		}
		applyClientLimits(cfg)
		return cfg, nil
	}

	if parameterName := strings.TrimSpace(os.Getenv("KUBECONFIG_PARAMETER_NAME")); parameterName != "" {
		cfg, err := loadFromParameter(context.Background(), parameterName)
		if err != nil {
			return nil, fmt.Errorf("build kubeconfig from KUBECONFIG_PARAMETER_NAME=%q: %w", parameterName, err)
		}
		applyClientLimits(cfg)
		return cfg, nil
	}

	if parameterPrefix := strings.TrimSpace(os.Getenv("KUBECONFIG_PARAMETER_PREFIX")); parameterPrefix != "" {
		cfg, err := loadFromParameterPrefix(context.Background(), parameterPrefix)
		if err != nil {
			return nil, fmt.Errorf("build kubeconfig from KUBECONFIG_PARAMETER_PREFIX=%q: %w", parameterPrefix, err)
		}
		applyClientLimits(cfg)
		return cfg, nil
	}

	if path := strings.TrimSpace(os.Getenv("KUBECONFIG")); path != "" {
		cfg, err := clientcmd.BuildConfigFromFlags("", path)
		if err != nil {
			return nil, fmt.Errorf("build kubeconfig from KUBECONFIG=%q: %w", path, err)
		}
		applyClientLimits(cfg)
		return cfg, nil
	}

	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf(
			"load in-cluster kubeconfig: %w (set KUBECONFIG_PATH or KUBECONFIG when running outside Kubernetes)",
			err,
		)
	}

	applyClientLimits(cfg)
	return cfg, nil
}

func applyClientLimits(cfg *rest.Config) {
	cfg.QPS = envFloat32("KUBE_API_QPS", defaultKubeAPIQPS)
	cfg.Burst = envInt("KUBE_API_BURST", defaultKubeAPIBurst)
}

func envFloat32(name string, def float32) float32 {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	f, err := strconv.ParseFloat(v, 32)
	if err != nil || f <= 0 {
		return def
	}
	return float32(f)
}

func envInt(name string, def int) int {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

func loadFromParameter(ctx context.Context, parameterName string) (*rest.Config, error) {
	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}

	out, err := ssm.NewFromConfig(awsCfg).GetParameter(ctx, &ssm.GetParameterInput{
		Name: &parameterName,
	})
	if err != nil {
		return nil, fmt.Errorf("get ssm parameter: %w", err)
	}
	if out.Parameter == nil || out.Parameter.Value == nil {
		return nil, fmt.Errorf("ssm parameter %q returned no value", parameterName)
	}

	cfg, err := clientcmd.RESTConfigFromKubeConfig([]byte(*out.Parameter.Value))
	if err != nil {
		return nil, fmt.Errorf("parse kubeconfig from ssm parameter: %w", err)
	}

	return cfg, nil
}

func loadFromParameterPrefix(ctx context.Context, parameterPrefix string) (*rest.Config, error) {
	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}

	parameterPrefix = strings.TrimRight(parameterPrefix, "/")
	names := []string{
		parameterPrefix + "/server",
		parameterPrefix + "/certificate-authority-data",
		parameterPrefix + "/client-certificate-data",
		parameterPrefix + "/client-key-data",
	}

	out, err := ssm.NewFromConfig(awsCfg).GetParameters(ctx, &ssm.GetParametersInput{
		Names: names,
	})
	if err != nil {
		return nil, fmt.Errorf("get ssm parameters: %w", err)
	}
	if len(out.InvalidParameters) > 0 {
		return nil, fmt.Errorf("invalid ssm parameters: %s", strings.Join(out.InvalidParameters, ", "))
	}

	values := make(map[string]string, len(out.Parameters))
	for _, parameter := range out.Parameters {
		if parameter.Name == nil || parameter.Value == nil {
			continue
		}
		values[*parameter.Name] = *parameter.Value
	}

	server := values[parameterPrefix+"/server"]
	caData := values[parameterPrefix+"/certificate-authority-data"]
	clientCertData := values[parameterPrefix+"/client-certificate-data"]
	clientKeyData := values[parameterPrefix+"/client-key-data"]
	if server == "" || caData == "" || clientCertData == "" || clientKeyData == "" {
		return nil, fmt.Errorf("ssm parameter prefix %q returned incomplete kubeconfig data", parameterPrefix)
	}

	kubeconfigData := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: cluster
  cluster:
    server: %s
    certificate-authority-data: %s
users:
- name: lambda
  user:
    client-certificate-data: %s
    client-key-data: %s
contexts:
- name: lambda@cluster
  context:
    cluster: cluster
    user: lambda
current-context: lambda@cluster
`, server, caData, clientCertData, clientKeyData)

	cfg, err := clientcmd.RESTConfigFromKubeConfig([]byte(kubeconfigData))
	if err != nil {
		return nil, fmt.Errorf("parse kubeconfig from ssm parameter prefix: %w", err)
	}

	return cfg, nil
}
