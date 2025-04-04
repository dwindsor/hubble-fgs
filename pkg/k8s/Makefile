# renovate: datasource=docker
BUILDER_IMAGE=docker.io/library/golang:1.24.2@sha256:991aa6a6e4431f2f01e869a812934bd60fbc87fb939e4a1ea54b8494ab9d2fc6
GO ?= go

all: generate

.PHONY: help
help:
	@echo 'Generated files:'
	@echo '    generate          - generate kubebuilder files'

.PHONY: generate
generate:
	../../contrib/repo-docker-run.sh \
		--env GOCACHE=/go/.cache \
		$(BUILDER_IMAGE) \
		make -C $(CURDIR) __do_generate

# Enterprise pkg/k8s is used as a replacement for OSS cilium/tetragon/pkg/k8s. It
# replaces the k8s v1alpha1 and factories with new ones that know both OSS and
# Enterprise types. This allows us to use OSS code to parse and manipulate the
# Enterprise CRDs, JSON, etc. using the message interfaces. However, for this
# to build correctly as a replace() pkg it can't self reference as
# isovalent/hubble-fgs/pkg/k8s/... because those are not technically the same
# pkgs after the replace. It causes go mod to import the enterprise pkg twice
# once as a replace in cilium/tetragon and once in isovalent/hubble-fgs with the
# tetragon version using the hubble-fgs version for those imports. The result is
# type reflect logic and asserts get confused and cause runtime panics. And any
# global state is duplicated and depending on wheres it initialized may be incorrect.
# Note asserts do not care if the types are identitical it only cares that they
# are exactly the same typespec ID. So we end up with panics when loading
# a CRD for example and the watcher tries to assert the type. To fix this runtime
# problem we import pkgs using cilium/tetragon/pkg/k8s. This is great once the
# replace() has happened it fixes the above runtime issues. However, it breaks
# the generate code because this is run before the replace(). So we quickly
# patch the imports, gen the code, and then revert the patch with some smallish
# sed lines.
.PHONY: __do_generate
__do_generate:
	find . -type f -name "*.go" -exec sed -i 's/cilium\/tetragon\/pkg\/k8s/isovalent\/hubble-fgs\/pkg\/k8s/g' {} +
	./tools/controller-gen crd paths=./apis/... output:dir=apis/cilium.io/client/crds/v1alpha1
	./tools/k8s-code-gen.sh
	find . -type f -name "*.go" -exec sed -i 's/isovalent\/hubble-fgs\/pkg\/k8s/cilium\/tetragon\/pkg\/k8s/g' {} +

.PHONY: vendor
vendor:
	$(GO) mod tidy
	$(GO) mod vendor
	$(GO) mod verify
	chmod +x vendor/k8s.io/code-generator/generate-internal-groups.sh
