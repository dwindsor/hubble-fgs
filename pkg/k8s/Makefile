include ../../Makefile.defs

# renovate: datasource=docker
BUILDER_IMAGE=docker.io/library/golang:1.26.4@sha256:68cb6d68bed024785b69195b89af7ac7a444f27791435f98647edff595aa0479
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
