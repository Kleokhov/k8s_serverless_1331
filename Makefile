SHELL := /usr/bin/env bash

GOOS ?= linux
GOARCH ?= amd64
CGO_ENABLED ?= 0

define build_lambda
	cd lambda && \
		GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=$(CGO_ENABLED) \
		go build -o "$(ARTIFACTS_DIR)/bootstrap" $(1)
endef

.PHONY: build-DispatcherFunction
build-DispatcherFunction:
	$(call build_lambda,./cmd/dispatcher)

.PHONY: build-ScheduleOneFunction
build-ScheduleOneFunction:
	$(call build_lambda,./cmd/scheduler/scheduleOne)

.PHONY: build-BinderFunction
build-BinderFunction:
	$(call build_lambda,./cmd/scheduler/binder)

.PHONY: build-BackoffFlushFunction
build-BackoffFlushFunction:
	$(call build_lambda,./cmd/scheduler/backoffFlush)

.PHONY: build-UnschedulableFlushFunction
build-UnschedulableFlushFunction:
	$(call build_lambda,./cmd/scheduler/unschedulableFlush)

.PHONY: build-PodGcFunction
build-PodGcFunction:
	$(call build_lambda,./cmd/controller/podgc)

.PHONY: build-JobControllerFunction
build-JobControllerFunction:
	$(call build_lambda,./cmd/controller/job)

.PHONY: build-TtlAfterFinishedFunction
build-TtlAfterFinishedFunction:
	$(call build_lambda,./cmd/controller/ttlafterfinished)

.PHONY: build-NamespaceControllerFunction
build-NamespaceControllerFunction:
	$(call build_lambda,./cmd/controller/namespace)
