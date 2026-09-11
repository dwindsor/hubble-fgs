include ../../Makefile.defs

# renovate: datasource=docker
BUILDER_IMAGE=docker.io/library/golang:1.27.1@sha256:f44f6e88636cfb311f9ebace870ded69d943f227bb3cb27d32ffd84ea18c43ea
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
	./tools/controller-gen crd paths=./apis/cilium.io/... output:dir=apis/cilium.io/client/crds/v1alpha1
	./tools/controller-gen object:headerFile=./tools/header.txt paths=./apis/cilium.io/... output:dir=apis/cilium.io/v1alpha1

.PHONY: vendor
vendor:
	$(GO) mod tidy
	$(GO) mod vendor
	$(GO) mod verify
