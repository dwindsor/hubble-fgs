include Makefile.defs
include $(OSS_DIR)/Makefile.defs

GO := go
INSTALL = $(QUIET)install
BINDIR ?= /usr/local/bin
CONTAINER_ENGINE ?= docker
DOCKER_IMAGE_TAG ?= latest
TETRAGON_IMAGE_NAME ?= isovalent/tetragon
OPERATOR_IMAGE_NAME ?= isovalent/tetragon-operator
LOCAL_CLANG ?= 0
LOCAL_CLANG_FORMAT ?= 0
FORMAT_FIND_FLAGS ?= -name '*.c' -o -name '*.h' -not -path 'bpf/include/vmlinux.h' -not -path 'bpf/include/api.h' -not -path 'bpf/libbpf/*'
NOOPT ?= 0
CLANG_IMAGE = quay.io/cilium/clang@sha256:b440ae7b3591a80ffef8120b2ac99e802bbd31dee10f5f15a48566832ae0866f
METADATA_IMAGE = quay.io/isovalent/hubble-enterprise-metadata
# Extra flags to pass to test binary
EXTRA_TESTFLAGS ?=
SUDO ?= sudo
GO_TEST_TIMEOUT ?= 20m

# Architecture, use TARGET_ARCH=amd64 or TARGET_ARCH=arm64
# or let uname detect the appropriate arch for native build
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
	TARGET_ARCH ?= amd64
endif
ifeq ($(UNAME_M),aarch64)
	TARGET_ARCH ?= arm64
endif
TARGET_ARCH ?= amd64

# Set GOARCH to TARGET_ARCH only if it's not set so that we can still use both
# GOARCH and TARGET_ARCH (make sense for pure Go program like tetragon-operator)
GOARCH ?= $(TARGET_ARCH)

ifeq ($(TARGET_ARCH),amd64)
	BPF_TARGET_ARCH ?= x86
endif
ifeq ($(TARGET_ARCH),arm64)
	BPF_TARGET_ARCH ?= arm64
endif
BPF_TARGET_ARCH ?= x86

BUILD_PKG_DIR ?= $(CURDIR)/build/$(TARGET_ARCH)
LIBBPF_INSTALL_DIR ?= ./lib
VERSION=$(shell git describe --tags --always --exclude 'api/*')

FS_SCANNER_BIN=bpf/objs/tetragon-fs-scanner
FS_SCANNER_RUNNER=bpf/objs/tetragon-runner 

# Directories to enforce copyright headers on
COPYRIGHT_DIRS = pkg/bench cmd/fgs-bench bpf/parsers/http

TESTER_PROGS_DIR = "contrib/tester-progs"
OSS_TESTER_PROGS_DIR = "$(OSS_DIR)/contrib/tester-progs"

# Do a parallel build with multiple jobs, based on the number of CPUs online
# in this system: 'make -j8' on a 8-CPU system, etc.
#
# (To override it, run 'make JOBS=1' and similar.)
#
JOBS ?= $(shell nproc)

__BPF_DEBUG_FLAGS :=
ifeq ($(DEBUG),1)
	NOOPT=1
	NOSTRIP=1
	__BPF_DEBUG_FLAGS += DEBUG=1
endif

# Branch in the OSS repo we want to sync with.
OSS_SYNC_TARGET ?= 

# GO_BUILD_LDFLAGS is initialized to empty use EXTRA_GO_BUILD_LDFLAGS to add link flags
GO_BUILD_LDFLAGS =
GO_BUILD_LDFLAGS += -X 'github.com/cilium/tetragon/pkg/version.Version=$(VERSION)'
ifeq ($(NOSTRIP),)
    # Note: these options will not remove annotations needed for stack
    # traces, so panic backtraces will still be readable.
    # -w: Omit the DWARF symbol table.
    # -s: Omit the symbol table and debug information.
    GO_BUILD_LDFLAGS += -s -w
endif
ifdef EXTRA_GO_BUILD_LDFLAGS
	GO_BUILD_LDFLAGS += $(EXTRA_GO_BUILD_LDFLAGS)
endif

# GO_BUILD_FLAGS is initialized to empty use EXTRA_GO_BUILD_FLAGS to add build flags
GO_BUILD_FLAGS =
GO_BUILD_FLAGS += -ldflags "$(GO_BUILD_LDFLAGS)"
ifeq ($(NOOPT),1)
	GO_BUILD_GCFLAGS = "all=-N -l"
    GO_BUILD_FLAGS += -gcflags=$(GO_BUILD_GCFLAGS)
endif
GO_BUILD_FLAGS += -mod=vendor
ifdef EXTRA_GO_BUILD_FLAGS
	GO_BUILD_FLAGS += $(EXTRA_GO_BUILD_FLAGS)
endif

GO_BUILD = CGO_ENABLED=0 GOARCH=$(GOARCH) $(GO) build $(GO_BUILD_FLAGS)

.PHONY: all
all: tetragon-bpf tetragon tetra fgs-bench test-compile tester-progs

-include Makefile.cli
-include Makefile.bundle
-include Makefile.olmindex

.PHONY: clean
clean: tarball-clean
	$(MAKE) -C ./bpf clean
	$(MAKE) -C $(TESTER_PROGS_DIR) clean
	rm -f go-tests/*.test ./ksyms ./tetra ./tetragon-operator ./tetragon ./fgs-alignchecker ./fgs-bench $(FS_SCANNER_BIN) $(FS_SCANNER_RUNNER)
	rm -fr ./release

##@ Build and install

.PHONY: tetragon hubble-fgs
hubble-fgs: | tetragon
tetragon: tetragon-fs-scanner ## Compile the Tetragon agent.
	$(GO_BUILD) ./cmd/tetragon

.PHONY: tetragon-operator hubble-enterprise-operator
hubble-enterprise-operator: | tetragon-operator
tetragon-operator: ## Compile the Tetragon operator.
	$(GO_BUILD) -o $@ ./operator

.PHONY: tetra hubble-enterprise
hubble-enterprise: | tetra
tetra: ## Compile the Tetragon gRPC client.
	$(GO_BUILD) ./cmd/tetra

.PHONY: tetragon-bpf hubble-bpf
hubble-bpf: | tetragon-bpf
ifeq (1,$(LOCAL_CLANG))
tetragon-bpf: tetragon-bpf-local ## Compile bpf programs.
else
tetragon-bpf: tetragon-bpf-container
endif

.PHONY: tetragon-bpf-local
tetragon-bpf-local:
	$(MAKE) -C ./bpf BPF_TARGET_ARCH=$(BPF_TARGET_ARCH) -j$(JOBS) $(__BPF_DEBUG_FLAGS)

.PHONY: tetragon-bpf-container
tetragon-bpf-container:
	$(CONTAINER_ENGINE) rm hubble-clang || true
	$(CONTAINER_ENGINE) run --rm -v $(CURDIR):/tetragon -u $$(id -u) --name hubble-clang $(CLANG_IMAGE) $(MAKE) -C /tetragon/bpf BPF_TARGET_ARCH=$(BPF_TARGET_ARCH) -j$(JOBS) $(__BPF_DEBUG_FLAGS)

.PHONY: fgs-bench
fgs-bench: ## Compile fgs-bench tool.
	$(GO) build ./cmd/fgs-bench

.PHONY: fgs-bench-graph
fgs-bench-graph:
	$(GO) build ./cmd/fgs-bench-graph

.PHONY: tetragon-fs-scanner
tetragon-fs-scanner:
	$(GO_BUILD) -buildvcs=false -o $(FS_SCANNER_BIN) ./cmd/tetragon-fs-scanner/
	$(CC) -static -Wall -Wextra -o $(FS_SCANNER_RUNNER) contrib/fs-scanner-runner/tetragon-runner.c

GO_BUILD_HOOK = CGO_ENABLED=0 GOARCH=$(GOARCH) $(GO) -C $(OSS_DIR)/contrib/tetragon-rthooks build $(GO_BUILD_FLAGS)

.PHONY: tetragon-oci-hook
tetragon-oci-hook:
	$(GO_BUILD_HOOK) -o $(shell realpath .)/$@ ./cmd/oci-hook

.PHONY: tetragon-oci-hook-setup
tetragon-oci-hook-setup:
	$(GO_BUILD_HOOK) -o $(shell realpath .)/$@ ./cmd/setup

.PHONY: tetragon-nri-hook
tetragon-nri-hook:
	$(GO_BUILD_HOOK) -o $(shell realpath .)/$@ ./cmd/nri-hook

.PHONY: ksyms
ksyms:
	make -C $(OSS_DIR) ksyms
	cp $(OSS_DIR)/ksyms ksyms

# Generate compile-commands.json using bear
.PHONY: compile-commands
compile-commands:
	$(MAKE) -C ./bpf clean
	bear -- $(MAKE) -C ./bpf

.PHONY: install
install:
	groupadd -f hubble
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 ./hubble-fgs $(DESTDIR)$(BINDIR)

##@ Container images

.PHONY: image
image: ## Build the Tetragon agent container image.
	$(CONTAINER_ENGINE) build -t "${TETRAGON_IMAGE_NAME}:${DOCKER_IMAGE_TAG}" --target release --platform=linux/${TARGET_ARCH} .
	@echo "Push like this when ready:"
	@echo "${CONTAINER_ENGINE} push ${TETRAGON_IMAGE_NAME}:$(DOCKER_IMAGE_TAG)"

.PHONY: image-operator
image-operator: ## Build the Tetragon operator container image.
	$(CONTAINER_ENGINE) build -f Dockerfile.operator -t "${OPERATOR_IMAGE_NAME}:${DOCKER_IMAGE_TAG}" --platform=linux/${TARGET_ARCH} .
	@echo "Push like this when ready:"
	@echo "${CONTAINER_ENGINE} push ${OPERATOR_IMAGE_NAME}:$(DOCKER_IMAGE_TAG)"

.PHONY: image-test
image-test:
	$(CONTAINER_ENGINE) build -f Dockerfile.test -t "isovalent/hubble-fgs-test:${DOCKER_IMAGE_TAG}" .
	@echo "Push like this when ready:"
	@echo "${CONTAINER_ENGINE} push isovalent/hubble-fgs-test:$(DOCKER_IMAGE_TAG)"

.PHONY: image-clang
image-clang:
	$(CONTAINER_ENGINE) build -f Dockerfile.clang -t "cilium/clang:${DOCKER_IMAGE_TAG}" .
	@echo "Push like this when ready:"
	@echo "${CONTAINER_ENGINE} push cilium/clang:$(DOCKER_IMAGE_TAG)"

##@ Packages

.PHONY: tarball
# Share same build environment as docker image
# Then it uses docker save to dump the layer and use it to
# contruct the tarball.
# Requires 'jq' to be installed
tarball: tarball-clean image ## Build Tetragon Enterprise compressed tarball.
	$(CONTAINER_ENGINE) build --build-arg TETRAGON_VERSION=$(VERSION) --build-arg TARGET_ARCH=$(TARGET_ARCH) -f Dockerfile.tarball -t "isovalent/tetragon-tarball:${DOCKER_IMAGE_TAG}" --platform=linux/${TARGET_ARCH} .
	$(QUIET)mkdir -p $(BUILD_PKG_DIR)
	$(CONTAINER_ENGINE) save isovalent/tetragon-tarball:$(DOCKER_IMAGE_TAG) -o $(BUILD_PKG_DIR)/tetragon-ee-$(VERSION)-$(TARGET_ARCH).tmp.tar
	$(QUIET)rm -fr $(BUILD_PKG_DIR)/docker/
	$(QUIET)mkdir -p $(BUILD_PKG_DIR)/docker/
	$(QUIET)rm -fr $(BUILD_PKG_DIR)/linux-tarball/
	$(QUIET)mkdir -p $(BUILD_PKG_DIR)/linux-tarball/
	tar xC $(BUILD_PKG_DIR)/docker/ -f $(BUILD_PKG_DIR)/tetragon-ee-$(VERSION)-$(TARGET_ARCH).tmp.tar
	sync $(BUILD_PKG_DIR)/docker/manifest.json
	cat $(BUILD_PKG_DIR)/docker/manifest.json
	cp "${BUILD_PKG_DIR}/docker/$$(jq -r '.[].Layers[0]' "${BUILD_PKG_DIR}/docker/manifest.json")" ${BUILD_PKG_DIR}/linux-tarball/tetragon-ee-$(VERSION)-$(TARGET_ARCH).tar
	@tar -tf ${BUILD_PKG_DIR}/linux-tarball/tetragon-ee-$(VERSION)-$(TARGET_ARCH).tar | grep "/usr/local/bin/tetragon" - \
		|| (echo "make: '$@' Error: could not find tetragon inside generated tarball"; exit 1)
	@rm -fr $(BUILD_PKG_DIR)/tetragon-ee-$(VERSION)-$(TARGET_ARCH).tmp.tar
	gzip -6 $(BUILD_PKG_DIR)/linux-tarball/tetragon-ee-$(VERSION)-$(TARGET_ARCH).tar
	@echo "tetragon tarball is ready: $(BUILD_PKG_DIR)/linux-tarball/tetragon-ee-$(VERSION)-$(TARGET_ARCH).tar.gz"

.PHONY: tarball-release
tarball-release: tarball ## Build Tetragon Enterprise release tarball.
	mkdir -p release/
	mv $(BUILD_PKG_DIR)/linux-tarball/tetragon-ee-$(VERSION)-$(TARGET_ARCH).tar.gz release/
	(cd release && sha256sum tetragon-ee-$(VERSION)-$(TARGET_ARCH).tar.gz > tetragon-ee-$(VERSION)-$(TARGET_ARCH).tar.gz.sha256sum)

.PHONY: tarball-clean
tarball-clean:
	rm -fr $(BUILD_PKG_DIR)

.PHONY: package-fgs-bench
package-fgs-bench: hubble-bpf-local fgs-bench
	tar --transform="s|^|fgs-bench/|" \
	    -czhf fgs-bench.tar.gz bpf/objs/*.o fgs-bench

##@ Test

# renovate: datasource=docker
GOLANGCILINT_IMAGE=docker.io/golangci/golangci-lint:v1.59.1@sha256:b5f8712114561f1e2fbe74d04ed07ddfd992768705033a6251f3c7b848eac38e
GOLANGCILINT_WANT_VERSION := $(subst @sha256,,$(patsubst v%,%,$(word 2,$(subst :, ,$(lastword $(subst /, ,$(GOLANGCILINT_IMAGE)))))))
GOLANGCILINT_VERSION = $(shell golangci-lint version 2>/dev/null)
ifneq (,$(findstring $(GOLANGCILINT_WANT_VERSION),$(GOLANGCILINT_VERSION)))
check: ## Run Go linters.
	golangci-lint run
else
check:
	docker run --rm -v `pwd`:/app -w /app --env GOTOOLCHAIN=auto $(GOLANGCILINT_IMAGE) golangci-lint run
endif

.PHONY: test
test: tester-progs hubble-bpf ## Run Go tests.
	$(SUDO) $(GO) test -p 1 -parallel 1 $(GOFLAGS) -gcflags=$(GO_BUILD_GCFLAGS) -timeout $(GO_TEST_TIMEOUT) -failfast -cover ./pkg/... ./cmd/... ./operator/... ${EXTRA_TESTFLAGS}

.PHONY: tester-progs
tester-progs:
	$(MAKE) -C $(TESTER_PROGS_DIR)
	$(MAKE) -C $(OSS_TESTER_PROGS_DIR)
	# NB(kkourt): This is not pretty, but we need it so that OSS testutils can find its contrib
	# programs. We can probably refactor OSS to deal with it, but that's for another day.
	ln -s -f $(OSS_DIR)/contrib vendor/github.com/cilium/tetragon/

.PHONY: tetragon-bpf-verify hubble-bpf-verify
hubble-bpf-verify: | tetragon-bpf-verify
tetragon-bpf-verify: tetragon-bpf ## Verify BPF programs.
	sudo contrib/fgs-verify-programs bpf/objs

.PHONY: alignchecker
alignchecker: ## Run alignchecker.
	$(GO) test -c ./pkg/alignchecker -o alignchecker

TEST_COMPILE ?= ./...
.PHONY: test-compile
test-compile: ## Compile Go tests.
	mkdir -p go-tests
	for pkg in $$($(GO) list "$(TEST_COMPILE)"); do \
		localpkg=$$(echo $$pkg | sed -e 's:github.com/isovalent/hubble-fgs/::'); \
		localtestfile=$$(echo $$localpkg | sed -e 's:/:.:g'); \
		numtests=$$(ls -l ./$$localpkg/*_test.go 2> /dev/null | wc -l); \
		if [ $$numtests -le 0 ]; then \
			continue; \
		fi; \
		echo -c ./$$localpkg -o go-tests/$$localtestfile; \
	done | GOMAXPROCS=1 xargs -P $(JOBS) -L 1 $(GO) test -gcflags=$(GO_BUILD_GCFLAGS)

.PHONY: fetch-testdata
fetch-testdata:
	docker stop fgs-md-temp || true
	docker rm fgs-md-temp || true
	docker create --name fgs-md-temp $(METADATA_IMAGE)
	mkdir -p testdata/btf
	docker cp fgs-md-temp:/var/run/tetragon-ee-metadata/vmlinux-5.4.104+ testdata/btf
	docker stop fgs-md-temp || true

E2E_TIMEOUT ?= 20m
# Agent image to use for end-to-end tests
E2E_AGENT ?= $(TETRAGON_IMAGE_NAME):$(DOCKER_IMAGE_TAG)
# Operator image to use for end-to-end tests
E2E_OPERATOR ?= $(OPERATOR_IMAGE_NAME):$(DOCKER_IMAGE_TAG)
# BTF file to use in the E2E test. Set to nothing to use system BTF.
E2E_BTF ?=
# Actual flags to use for BTF file in e2e test. Use E2E_BTF instead.
ifneq ($(E2E_BTF),)
	E2E_BTF_FLAGS ?= -tetragon.btf="$(shell readlink -f $(E2E_BTF))"
endif
# Build image and operator images locally before running test. Set to 0 to disable.
E2E_BUILD_IMAGES ?= 1
ifneq ($(GO_BUILD_GCFLAGS),)
	E2E_GO_BUILD_GCFLAGS ?= -gcflags=$(GO_BUILD_GCFLAGS)
endif
ifeq ($(E2E_COVER),1)
	E2E_COVER_FLAG ?= -cover
endif
E2E_TESTS ?= ./tests/e2e/tests/helm/...

## e2e-test: ## run e2e tests
## e2e-test E2E_BUILD_IMAGES=0: ## run e2e tests without (re-)building images
## e2e-test E2E_TESTS=./tests/e2e/tests/skeleton: ## run a specific e2e test
.PHONY: e2e-test
ifneq ($(E2E_BUILD_IMAGES), 0)
e2e-test: image image-operator
else
e2e-test:
endif
	$(GO) test -p 1 -parallel 1 $(E2E_COVER_FLAG) $(E2E_GO_BUILD_GCFLAGS)  \
		-timeout $(E2E_TIMEOUT) ${E2E_EXTRA_GOTEST_FLAGS}              \
		${E2E_TESTS} ${E2E_EXTRA_TEST_FLAGS} $(E2E_BTF_FLAGS)          \
		-tetragon.helm.set tetragon.image.override="$(E2E_AGENT)"      \
		-tetragon.helm.set tetragonOperator.image.override="$(E2E_OPERATOR)"

.PHONY: parsertest
parsertest: ## Run parser Go tests.
	$(GO) test -c ./pkg/parsertest -o parsertest

.PHONY: parsertest-gen
parsertest-gen:
	$(GO_BUILD) ./cmd/parsertest-gen

##@ Development

.PHONY: cscope
cscope: ## Generate cscope for bpf files.
	find bpf -name "*.[chxsS]" -print > cscope.files
	cscope -b -q -k

.PHONY: kind
kind: ## Create a kind cluster for Tetragon development.
	$(MAKE) -C $(OSS_DIR) kind

KIND_BUILD_IMAGES ?= 1
export TETRAGON_KIND_BASE_VALUES = ./contrib/kind/values.yaml
export TETRAGON_KIND_HELM_CHART = ./install/kubernetes/tetragon

## kind-install-tetragon: ## Install Tetragon in a kind cluster.
## kind-install-tetragon KIND_BUILD_IMAGES=0: ## Install Tetragon in a kind cluster without (re-)building images.
## kind-install-tetragon VALUES=values.yaml: ## Install Tetragon in a kind cluster using additional Helm values.
.PHONY: kind-install-tetragon
ifneq ($(KIND_BUILD_IMAGES), 0)
kind-install-tetragon: image image-operator
else
kind-install-tetragon:
endif
ifneq ($(VALUES),)
	$(OSS_DIR)/contrib/kind/install-tetragon.sh -v $(VALUES)
else
	$(OSS_DIR)/contrib/kind/install-tetragon.sh
endif

.PHONY: kind-setup
kind-setup: kind kind-install-tetragon ## Create a kind cluster and install local version of Tetragon.

.PHONY: kind-down
kind-down: ## Delete a kind cluster for Tetragon development.
	$(MAKE) -C $(OSS_DIR) kind-down

##@ Chores and generated files

.PHONY: codegen protogen
codegen: | protogen
protogen: protoc-gen-go-tetragon ## Generate code based on .proto files.
	# Need to call vendor twice here, once before and once after codegen the reason
	# being we need to grab changes first plus pull in whatever gets generated here.
	$(MAKE) -C api vendor
	$(MAKE) -C api
	$(GO) mod tidy
	$(GO) mod vendor
	$(GO) mod verify

.PHONY: protoc-gen-go-tetragon
protoc-gen-go-tetragon:
	$(GO_BUILD) -o bin/$@ ./tools/protoc-gen-go-tetragon/

.PHONY: generate crds
generate: | crds
crds: ## Generate kubebuilder files.
	# Need to call vendor twice here, once before and once after generate, the reason
	# being we need to grab changes first plus pull in whatever gets generated here.
	$(MAKE) -C pkg/k8s vendor
	$(MAKE) -C pkg/k8s
	$(MAKE) -C pkg/k8s vendor
	$(GO) mod tidy
	$(GO) mod vendor
	$(GO) mod verify

.PHONY: vendor
vendor: ## Tidy and vendor Go modules.
	$(MAKE) -C api vendor
	$(MAKE) -C pkg/k8s vendor
	$(GO) mod tidy
	$(GO) mod vendor
	$(GO) mod verify

.PHONY: clang-format
ifeq (1,$(LOCAL_CLANG_FORMAT))
clang-format: ## Run code formatter on BPF code.
	find bpf $(FORMAT_FIND_FLAGS) | xargs -n 1000 clang-format -i -style=file
else
clang-format:
	$(CONTAINER_ENGINE) build -f Dockerfile.clang-format -t "isovalent/clang-format:${DOCKER_IMAGE_TAG}" .
	find bpf $(FORMAT_FIND_FLAGS) | xargs -n 1000 \
		$(CONTAINER_ENGINE) run -v $(shell realpath .):/fgs "isovalent/clang-format:${DOCKER_IMAGE_TAG}" -i -style=file
endif

.PHONY: go-format
go-format: ## Run code formatter on Go code.
	find . -name '*.go' -not -path './vendor/*' -not -path './api/vendor/*' -not -path './pkg/k8s/vendor/*' -not -path './modules/*' -not -path './api/v1/tetragon/*' | xargs gofmt -w

.PHONY: format
format: go-format clang-format ## Convenience alias for clang-format and go-format.

.PHONY: generate-flags
generate-flags: tetragon ## Generate Tetragon daemon flags for documentation.
	echo "$$(./tetragon --generate-docs)" > docs/configuration/tetragon_flags.yaml

METRICS_DOCS_PATH := docs/metrics/metrics.md

.PHONY: tetragon-metrics-docs
tetragon-metrics-docs:
	$(GO_BUILD) ./cmd/tetragon-metrics-docs/

.PHONY: metrics-docs
metrics-docs: tetragon-metrics-docs ## Generate metrics reference.
	echo '<!-- This file is autogenerated via `make metrics-docs` please do not edit directly. -->' > $(METRICS_DOCS_PATH)
	echo "" >> $(METRICS_DOCS_PATH)
	$(CONTAINER_ENGINE) run --rm -v $(PWD):$(PWD) -w $(PWD) $(GO_IMAGE) ./tetragon-metrics-docs health >> $(METRICS_DOCS_PATH)
	$(CONTAINER_ENGINE) run --rm -v $(PWD):$(PWD) -w $(PWD) $(GO_IMAGE) ./tetragon-metrics-docs resources >> $(METRICS_DOCS_PATH)
	$(CONTAINER_ENGINE) run --rm -v $(PWD):$(PWD) -w $(PWD) $(GO_IMAGE) ./tetragon-metrics-docs health-dns >> $(METRICS_DOCS_PATH)
	$(CONTAINER_ENGINE) run --rm -v $(PWD):$(PWD) -w $(PWD) $(GO_IMAGE) ./tetragon-metrics-docs health-file >> $(METRICS_DOCS_PATH)
	$(CONTAINER_ENGINE) run --rm -v $(PWD):$(PWD) -w $(PWD) $(GO_IMAGE) ./tetragon-metrics-docs health-http >> $(METRICS_DOCS_PATH)
	$(CONTAINER_ENGINE) run --rm -v $(PWD):$(PWD) -w $(PWD) $(GO_IMAGE) ./tetragon-metrics-docs health-network >> $(METRICS_DOCS_PATH)
	$(CONTAINER_ENGINE) run --rm -v $(PWD):$(PWD) -w $(PWD) $(GO_IMAGE) ./tetragon-metrics-docs health-tls >> $(METRICS_DOCS_PATH)
	$(CONTAINER_ENGINE) run --rm -v $(PWD):$(PWD) -w $(PWD) $(GO_IMAGE) ./tetragon-metrics-docs events >> $(METRICS_DOCS_PATH)
	$(CONTAINER_ENGINE) run --rm -v $(PWD):$(PWD) -w $(PWD) $(GO_IMAGE) ./tetragon-metrics-docs dns >> $(METRICS_DOCS_PATH)
	$(CONTAINER_ENGINE) run --rm -v $(PWD):$(PWD) -w $(PWD) $(GO_IMAGE) ./tetragon-metrics-docs file >> $(METRICS_DOCS_PATH)
	$(CONTAINER_ENGINE) run --rm -v $(PWD):$(PWD) -w $(PWD) $(GO_IMAGE) ./tetragon-metrics-docs http >> $(METRICS_DOCS_PATH)
	$(CONTAINER_ENGINE) run --rm -v $(PWD):$(PWD) -w $(PWD) $(GO_IMAGE) ./tetragon-metrics-docs icmp >> $(METRICS_DOCS_PATH)
	$(CONTAINER_ENGINE) run --rm -v $(PWD):$(PWD) -w $(PWD) $(GO_IMAGE) ./tetragon-metrics-docs interface >> $(METRICS_DOCS_PATH)
	$(CONTAINER_ENGINE) run --rm -v $(PWD):$(PWD) -w $(PWD) $(GO_IMAGE) ./tetragon-metrics-docs tcp >> $(METRICS_DOCS_PATH)
	$(CONTAINER_ENGINE) run --rm -v $(PWD):$(PWD) -w $(PWD) $(GO_IMAGE) ./tetragon-metrics-docs udp >> $(METRICS_DOCS_PATH)
	$(CONTAINER_ENGINE) run --rm -v $(PWD):$(PWD) -w $(PWD) $(GO_IMAGE) ./tetragon-metrics-docs rawsocket >> $(METRICS_DOCS_PATH)
	$(CONTAINER_ENGINE) run --rm -v $(PWD):$(PWD) -w $(PWD) $(GO_IMAGE) ./tetragon-metrics-docs tls >> $(METRICS_DOCS_PATH)

.PHONY: lint-metrics-md
lint-metrics-md: metrics-docs ## Check if metrics reference is up to date.
	@if [ -n "$$(git status --porcelain $(METRICS_DOCS_PATH))" ]; then \
		echo "metrics doc out of sync; please run 'make metrics-docs'" > /dev/stderr; \
		false; \
	fi

.PHONY: update-copyright
update-copyright: ## Update copyright headers.
	for dir in $(COPYRIGHT_DIRS); do \
		contrib/copyright-headers update $$dir; \
	done

.PHONY: check-copyright
check-copyright: ## Check copyright headers.
	for dir in $(COPYRIGHT_DIRS); do \
		contrib/copyright-headers check $$dir; \
	done

##@ OSS submodule helpers

.PHONY: oss-sync
oss-sync: ## Sync OSS submodule and create an oss-sync commit.
	@echo Syncing OSS submodule...
	@./contrib/oss-chores/oss-sync.sh "$(OSS_SYNC_TARGET)"

.PHONY: oss-init
oss-init: ## Initialize the OSS submodule.
	@echo Initializing and updating submodules...
	git submodule update --init $(OSS_DIR)

.PHONY: oss-checkout
oss-checkout: ## Pull in OSS code that matches the current registered version and update everything (codegen, go modules).
	@echo Updating submodule to match the registered version...
	git submodule update $(OSS_DIR)
	# Codegen is vendored, so we need to run make generate && make codegen here to
	# pick up changes.
	@echo Generating code...
	make generate && make codegen
	# NB, we need to vendor for a second time here since codegen may have introduced
	# new dependencies.
	@echo Vendoring and verifiying modules...
	make vendor

.PHONY: oss-update
oss-update: ## Pull in latest OSS code and update everything (codegen, go modules).
	# Update the submodule and vendor any changes.
	@echo Updating submodule...
	git submodule update --remote $(OSS_DIR)
	@echo Vendoring and verifiying modules...
	make vendor
	# Codegen is vendored, so we need to run make generate && make codegen here to
	# pick up changes.
	@echo Generating code...
	make generate && make codegen
	# NB, we need to vendor for a second time here since codegen may have introduced
	# new dependencies.
	@echo Vendoring and verifiying modules...
	make vendor

##@ Documentation

.PHONY: help
help:  ## Display this help, based on https://www.thapaliya.com/en/writings/well-documented-makefiles/
	$(call print_help_from_comments)

.PHONY: version chart-version
version: ## Print Tetragon version.
	@echo $(VERSION)

chart-version: ## Print Tetragon OCI Helm chart version.
	@echo $(VERSION) | sed 's/^v\(.*\)/\1/'
