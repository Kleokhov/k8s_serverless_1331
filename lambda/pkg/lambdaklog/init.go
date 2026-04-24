package lambdaklog

import (
	"flag"
	"log"
	"os"
	"sync"

	"k8s.io/klog/v2"
)

const (
	defaultVerbosity = "5"
	defaultToStderr  = "true"
)

var initOnce sync.Once

func Init() {
	initOnce.Do(func() {
		klog.InitFlags(nil)

		setFlag("v", envOrDefault("KLOG_VERBOSITY", defaultVerbosity))
		setFlag("logtostderr", envOrDefault("KLOG_TO_STDERR", defaultToStderr))
	})
}

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func setFlag(name, value string) {
	if err := flag.CommandLine.Set(name, value); err != nil {
		log.Printf("klog init: failed to set -%s=%s: %v", name, value, err)
	}
}
