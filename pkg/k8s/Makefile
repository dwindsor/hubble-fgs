include ../../Makefile.defs

# renovate: datasource=docker
BUILDER_IMAGE=docker.io/library/golang:1.26.1@sha256:595c7847cff97c9a9e76f015083c481d26078f961c9c8dca3923132f51fe12f1
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
