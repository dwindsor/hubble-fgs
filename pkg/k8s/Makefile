# renovate: datasource=docker
BUILDER_IMAGE=docker.io/library/golang:1.24.3@sha256:39d9e7d9c5d9c9e4baf0d8fff579f06d5032c0f4425cdec9e86732e8e4e374dc
GO ?= go

all: generate

.PHONY: help
help:
	@echo 'Generated files:'
	@echo '    generate          - generate kubebuilder files'

.PHONY: generate
generate:
	../../contrib/scripts/repo-docker-run.sh \
		--env GOCACHE=/go/.cache \
		--volume $(CURDIR)/../..:/src \
		--workdir /src/pkg/k8s \
		$(BUILDER_IMAGE) \
		make __do_generate

.PHONY: __do_generate
__do_generate:
	./tools/controller-gen crd paths=./apis/... output:dir=apis/cilium.io/client/crds/v1alpha1

.PHONY: vendor
vendor:
	$(GO) mod tidy
	$(GO) mod vendor
	$(GO) mod verify
