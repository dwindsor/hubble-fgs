# renovate: datasource=docker
BUILDER_IMAGE=docker.io/library/golang:1.25.3@sha256:6ea52a02734dd15e943286b048278da1e04eca196a564578d718c7720433dbbe
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
	./tools/controller-gen object:headerFile=./tools/header.txt paths=./apis/... output:dir=apis/cilium.io/v1alpha1

.PHONY: vendor
vendor:
	$(GO) mod tidy
	$(GO) mod vendor
	$(GO) mod verify
