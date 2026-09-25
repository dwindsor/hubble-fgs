include Makefile.defs

INSTALL = $(QUIET)install
BINDIR ?= /usr/local/bin
DOCKER_IMAGE_TAG ?= latest
TETRAGON_IMAGE_NAME ?= isovalent/tetragon
TETRAGON_SLIM_IMAGE_NAME ?= isovalent/tetragon-slim
AGGREGATOR_IMAGE_NAME ?= isovalent/tetragon-aggregator
OPERATOR_IMAGE_NAME ?= isovalent/tetragon-operator
RTHOOKS_IMAGE_NAME ?= isovalent/tetragon-rthooks
LOCAL_CLANG ?= 0
LOCAL_CLANG_FORMAT ?= 0
FORMAT_FIND_FLAGS ?= -name '*.c' -o -name '*.h'
NOOPT ?= 0
CLANG_IMAGE = quay.io/cilium/clang:969f95f8ef7923af36bf657ba6d4c65691f56882@sha256:ff83e52d3ea150b3d93e4ae40ae86620003ac3f6d91fe6e939dcc95469f83ff2
METADATA_IMAGE = quay.io/isovalent/hubble-enterprise-metadata
# Extra flags to pass to test binary
EXTRA_TESTFLAGS ?=
SUDO ?= sudo
GO_TEST_TIMEOUT ?= 20m
GO_TEST_PACKAGES ?= ./pkg/... ./cmd/... ./operator/...
CONTAINER_ENGINE_ARGS ?=
LSEG ?= 0
# renovate: datasource=github-releases depName=helm/helm
HELM_VERSION := v4.2.3

comma := ,
TEST_TAGS := sudo_tests
TETRAGON_TAGS :=
ifeq ($(LSEG),1)
	TETRAGON_TAGS := $(TETRAGON_TAGS)$(if $(TETRAGON_TAGS),$(comma))lseg
	TEST_TAGS := $(TEST_TAGS)$(if $(TEST_TAGS),$(comma))lseg
endif
TETRAGON_TAGS_ARG := $(if $(TETRAGON_TAGS),-tags $(TETRAGON_TAGS),)

TETRAGON_NOK8S_TAGS := $(TETRAGON_TAGS)$(if $(TETRAGON_TAGS),$(comma))nok8s
TETRAGON_NOK8S_TAGS_ARG := -tags $(TETRAGON_NOK8S_TAGS)

# The slim build additionally drops cloud-provider code (AWS SDK, etc.) via the
# nocloud tag, on top of nok8s.
TETRAGON_SLIM_TAGS := $(TETRAGON_NOK8S_TAGS)$(comma)nocloud
TETRAGON_SLIM_TAGS_ARG := -tags $(TETRAGON_SLIM_TAGS)

# Architecture, use TARGET_ARCH=amd64 or TARGET_ARCH=arm64
# or let uname detect the appropriate arch for native build
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
	TARGET_ARCH ?= amd64
endif
ifeq ($(filter $(UNAME_M),aarch64 arm64),$(UNAME_M))
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
VERSION=$(shell (git describe --tags --always --exclude 'api/*' --exclude '*-codedrop' 2>/dev/null || git describe --tags --always --exclude '*-codedrop' 2>/dev/null || git describe --always 2>/dev/null || echo "UNKNOWN_GIT_VERSION!") | sed 's|^api/||')

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
GO_BUILD_LDFLAGS += -X 'github.com/cilium/tetragon/pkg/version.Name=tetragon-enterprise'
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

GO_BUILD      = CGO_ENABLED=0 GOARCH=$(GOARCH) $(GO) build $(GO_BUILD_FLAGS)
GO_BUILD_NOK8S := $(GO_BUILD) -overlay pkg/tracingpolicy/nok8s-embed-overlay.json
GO_BUILD_SLIM := $(subst version.Name=tetragon-enterprise,version.Name=tetragon-slim,$(GO_BUILD_NOK8S))

.PHONY: all
all: tetragon-bpf tetragon tetra fgs-bench test-compile tester-progs

-include Makefile.cli
-include Makefile.bundle
-include Makefile.olmindex

.PHONY: clean
clean: tarball-clean
	$(MAKE) -C ./bpf clean
	$(MAKE) -C $(TESTER_PROGS_DIR) clean
	rm -f go-tests/*.test ./ksyms ./tetra ./tetragon-aggregator ./tetragon-operator ./tetragon ./fgs-alignchecker ./fgs-bench $(FS_SCANNER_BIN) $(FS_SCANNER_RUNNER)
	rm -fr ./release

##@ Build and install

.PHONY: tetragon
tetragon: tetragon-fs-scanner ## Compile the Tetragon agent.
	$(GO_BUILD) $(TETRAGON_TAGS_ARG) ./cmd/tetragon

.PHONY: tetragon-nok8s
tetragon-nok8s: tetragon-fs-scanner ## Compile the Tetragon agent (nok8s build).
	$(GO_BUILD_NOK8S) -o $@ $(TETRAGON_NOK8S_TAGS_ARG) ./cmd/tetragon

.PHONY: tetragon-aggregator
tetragon-aggregator: ## Compile the Tetragon aggregator
	$(GO_BUILD) -o $@ ./aggregator

.PHONY: tetragon-operator
tetragon-operator: ## Compile the Tetragon operator.
	$(GO_BUILD) -o $@ ./operator

.PHONY: tetra
tetra: ## Compile the Tetragon gRPC client.
	$(GO_BUILD) ./cmd/tetra

.PHONY: tetra-nok8s
tetra-nok8s: ## Compile the Tetragon gRPC client (nok8s build)
	$(GO_BUILD_NOK8S) -o $@ $(TETRAGON_NOK8S_TAGS_ARG) ./cmd/tetra

.PHONY: tetrabox
tetrabox: tetragon-runner ## Compile single multi-call tetragon binary
	$(GO_BUILD_SLIM) -o $@ $(TETRAGON_SLIM_TAGS_ARG) ./cmd/tetrabox
	# set up symlinks so that things work
	rm -f tetra tetragon $(FS_SCANNER_BIN)
	ln -s tetrabox tetra
	ln -s tetrabox tetragon
	ln -s `dirname $(FS_SCANNER_BIN) | sed -e 's:[^/]\+:..:g'`/tetrabox $(FS_SCANNER_BIN)

.PHONY: tetrabox-k8s
tetrabox-k8s: tetragon-runner ## Compile single multi-call tetragon binary
	$(GO_BUILD) -o $@ ./cmd/tetrabox
	# set up symlinks so that things work
	rm -f tetra tetragon $(FS_SCANNER_BIN)
	ln -s $@ tetra
	ln -s $@ tetragon
	ln -s `dirname $(FS_SCANNER_BIN) | sed -e 's:[^/]\+:..:g'`/$@ $(FS_SCANNER_BIN)

.PHONY: tetragon-bpf
ifeq (1,$(LOCAL_CLANG))
tetragon-bpf: tetragon-bpf-local ## Compile bpf programs.
else
tetragon-bpf: tetragon-bpf-container
endif

.PHONY: tetragon-bpf-local
tetragon-bpf-local:
	$(MAKE) -C ./bpf BPF_TARGET_ARCH=$(BPF_TARGET_ARCH) -j$(JOBS) $(__BPF_DEBUG_FLAGS) LSEG=$(LSEG)

.PHONY: tetragon-bpf-container
tetragon-bpf-container:
	$(CONTAINER_ENGINE) rm tetragon-clang || true
	$(CONTAINER_ENGINE) run --rm -v $(CURDIR):/tetragon -u $$(id -u) --name tetragon-clang $(CLANG_IMAGE) $(MAKE) -C /tetragon/bpf BPF_TARGET_ARCH=$(BPF_TARGET_ARCH) -j$(JOBS) $(__BPF_DEBUG_FLAGS) LSEG=$(LSEG)

.PHONY: fgs-bench
fgs-bench: ## Compile fgs-bench tool.
	$(GO) build ./cmd/fgs-bench

.PHONY: fgs-bench-graph
fgs-bench-graph:
	$(GO) build ./cmd/fgs-bench-graph


.PHONY: tetragon-runner
tetragon-runner:
	mkdir -p `dirname $(FS_SCANNER_RUNNER)`
	$(CC) -static -Wall -Wextra -o $(FS_SCANNER_RUNNER) contrib/fs-scanner-runner/tetragon-runner.c

.PHONY: tetragon-fs-scanner
tetragon-fs-scanner: tetragon-runner
	$(GO_BUILD) -buildvcs=false -o $(FS_SCANNER_BIN) ./cmd/tetragon-fs-scanner/

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

##@ Container images

.PHONY: image
image: ## Build the Tetragon agent container image.
	$(CONTAINER_ENGINE) build -t "${TETRAGON_IMAGE_NAME}:${DOCKER_IMAGE_TAG}" --build-arg DEBUG=${DEBUG} --build-arg LSEG=$(LSEG) --target release --platform=linux/${TARGET_ARCH} ${CONTAINER_ENGINE_ARGS} .
	@echo "Push like this when ready:"
	@echo "${CONTAINER_ENGINE} push ${TETRAGON_IMAGE_NAME}:$(DOCKER_IMAGE_TAG)"

.PHONY: image-slim
image-slim: ## Build the Tetragon agent container image.
	$(CONTAINER_ENGINE) build -f Dockerfile.slim -t "${TETRAGON_SLIM_IMAGE_NAME}:${DOCKER_IMAGE_TAG}" --build-arg DEBUG=${DEBUG} --target release --platform=linux/${TARGET_ARCH} ${CONTAINER_ENGINE_ARGS} .
	@echo "Push like this when ready:"
	@echo "${CONTAINER_ENGINE} push ${TETRAGON_SLIM_IMAGE_NAME}:$(DOCKER_IMAGE_TAG)"

.PHONY: image-aggregator
image-aggregator: ## Build the Tetragon aggregator container image.
	$(CONTAINER_ENGINE) build -f Dockerfile.aggregator -t "${AGGREGATOR_IMAGE_NAME}:${DOCKER_IMAGE_TAG}" --platform=linux/${TARGET_ARCH} .
	@echo "Push like this when ready:"
	@echo "${CONTAINER_ENGINE} push ${AGGREGATOR_IMAGE_NAME}:$(DOCKER_IMAGE_TAG)"

.PHONY: image-rthooks
image-rthooks:
	$(CONTAINER_ENGINE) build -f Dockerfile.rthooks -t "${RTHOOKS_IMAGE_NAME}:${DOCKER_IMAGE_TAG}" --platform=linux/${TARGET_ARCH} .
	@echo "Push like this when ready:"
	@echo "${CONTAINER_ENGINE} push ${RTHOOKS_IMAGE_NAME}:${DOCKER_IMAGE_TAG}"

.PHONY: image-operator
image-operator: ## Build the Tetragon operator container image.
	$(CONTAINER_ENGINE) build -f Dockerfile.operator -t "${OPERATOR_IMAGE_NAME}:${DOCKER_IMAGE_TAG}" --platform=linux/${TARGET_ARCH} .
	@echo "Push like this when ready:"
	@echo "${CONTAINER_ENGINE} push ${OPERATOR_IMAGE_NAME}:$(DOCKER_IMAGE_TAG)"

.PHONY: image-clang
image-clang:
	$(CONTAINER_ENGINE) build -f Dockerfile.clang -t "cilium/clang:${DOCKER_IMAGE_TAG}" .
	@echo "Push like this when ready:"
	@echo "${CONTAINER_ENGINE} push cilium/clang:$(DOCKER_IMAGE_TAG)"

##@ Packages

TBALL_DOCKER_BUILD_ARGS=--build-arg TETRAGON_VERSION=$(VERSION) --build-arg TARGET_ARCH=$(TARGET_ARCH) --platform=linux/${TARGET_ARCH}

## normal tarball
TBALL_IMAGE=isovalent/tetragon-tarball:$(DOCKER_IMAGE_TAG)
TBALL_NAME=tetragon-ee-$(VERSION)-$(TARGET_ARCH)
TBALL_TGZ=$(BUILD_PKG_DIR)/linux-tarball/$(TBALL_NAME).tar.gz

.PHONY: tarball

tarball: tarball-clean image ## Build Tetragon Enterprise compressed tarball.
	$(CONTAINER_ENGINE) build $(TBALL_DOCKER_BUILD_ARGS) -f Dockerfile.tarball -t $(TBALL_IMAGE) .
	$(QUIET)mkdir -p $$(dirname $(TBALL_TGZ))
	$(QUIET)./contrib/scripts/image2targz $(TBALL_IMAGE) $(TBALL_TGZ) $(TBALL_NAME)
	@/bin/echo "tetragon tgz ready: $(TBALL_TGZ)"

.PHONY: tarball-release
tarball-release: tarball ## Build Tetragon Enterprise release tarball.
	mkdir -p release/
	mv $(BUILD_PKG_DIR)/linux-tarball/tetragon-ee-$(VERSION)-$(TARGET_ARCH).tar.gz release/
	(cd release && sha256sum tetragon-ee-$(VERSION)-$(TARGET_ARCH).tar.gz > tetragon-ee-$(VERSION)-$(TARGET_ARCH).tar.gz.sha256sum)


## slim tarball
TBALL_SLIM_IMAGE=isovalent/tetragon-slim-tarball:$(DOCKER_IMAGE_TAG)
TBALL_SLIM_NAME=tetragon-slim-$(VERSION)-$(TARGET_ARCH)
TBALL_SLIM_TGZ=$(BUILD_PKG_DIR)/linux-tarball/$(TBALL_SLIM_NAME).tar.gz

.PHONY: tarball-slim-extract
tarball-slim-extract: tarball-clean image-slim ## Extract Tetragon slim in a directory under /tmp
	$(CONTAINER_ENGINE) build $(TBALL_DOCKER_BUILD_ARGS) -f Dockerfile.slim.tarball -t $(TBALL_SLIM_IMAGE) .
	@xdir=$$(mktemp --tmpdir -d "tetragon-slim.XXXXXXXX") && \
		./contrib/scripts/image2dir $(TBALL_SLIM_IMAGE) $$xdir $(TBALL_SLIM_NAME) && \
		/bin/echo "tetragon slim is extracted in: $$xdir. Start with $$xdir/$(TBALL_SLIM_NAME)/start.sh."

.PHONY: tarball-slim
tarball-slim: tarball-clean image-slim ## Build Tetragon slim compressed tarball.
	$(CONTAINER_ENGINE) build $(TBALL_DOCKER_BUILD_ARGS) -f Dockerfile.slim.tarball -t $(TBALL_SLIM_IMAGE) .
	$(QUIET)mkdir -p $$(dirname $(TBALL_SLIM_TGZ))
	./contrib/scripts/image2targz $(TBALL_SLIM_IMAGE) $(TBALL_SLIM_TGZ) $(TBALL_SLIM_NAME)
	@/bin/echo "tetragon slim tgz ready: $(TBALL_SLIM_TGZ)"

.PHONY: tarball-slim-release
tarball-slim-release: tarball-slim ## Build Tetragon slim release tarball.
	mkdir -p release/
	mv $(TBALL_SLIM_TGZ) release/
	(cd release && sha256sum $$(basename $(TBALL_SLIM_TGZ)) > tetragon-slim-$(VERSION)-$(TARGET_ARCH).tar.gz.sha256sum)

.PHONY: tarball-clean
tarball-clean:
	rm -fr $(BUILD_PKG_DIR)

.PHONY: package-fgs-bench
package-fgs-bench: tetragon-bpf-local fgs-bench
	tar --transform="s|^|fgs-bench/|" \
	    -czhf fgs-bench.tar.gz bpf/objs/*.o fgs-bench

##@ Test

# renovate: datasource=docker
GOLANGCILINT_IMAGE=docker.io/golangci/golangci-lint:v2.14.0@sha256:ad862ba6b3798cbe0fd9fd7408d498fd74fbd2623a92406b2fd3898faf0bf98f
GOLANGCILINT_WANT_VERSION := $(subst @sha256,,$(patsubst v%,%,$(word 2,$(subst :, ,$(lastword $(subst /, ,$(GOLANGCILINT_IMAGE)))))))
GOLANGCILINT_VERSION = $(shell golangci-lint version 2>/dev/null)
ifneq (,$(findstring $(GOLANGCILINT_WANT_VERSION),$(GOLANGCILINT_VERSION)))
GOLANGCILINT_BIN = golangci-lint
else
GOLANGCILINT_BIN = docker run --rm -v `pwd`:/app -w /app --env GOTOOLCHAIN=auto $(GOLANGCILINT_IMAGE) golangci-lint
endif

.PHONY: check
check: ## Run Go linters.
	$(GOLANGCILINT_BIN) run

.PHONY: copy-golangci-lint
copy-golangci-lint:
	mkdir -p bin/
	$(eval xid=$(shell $(CONTAINER_ENGINE) create $(GOLANGCILINT_IMAGE)))
	echo ${xid}
	docker cp ${xid}:/usr/bin/golangci-lint bin/golangci-lint
	docker rm ${xid}

## unit-test: ## Run Go unit tests without any external dependencies.
.PHONY: unit-test
unit-test:
	$(GO) test ./...

.PHONY: test
test: tester-progs tetragon-bpf tetragon-bpf-test ## Run Go tests.
	# A workaround for https://github.com/golang/go/issues/75031
	$(GO) env -w GOTOOLCHAIN=go1.25.0+auto
	$(GO) test -exec "$(SUDO)" -tags $(TEST_TAGS) -p 1 -parallel 1 $(GOFLAGS) -gcflags=$(GO_BUILD_GCFLAGS) -timeout $(GO_TEST_TIMEOUT) -failfast -cover $(GO_TEST_PACKAGES) ${EXTRA_TESTFLAGS}

.PHONY: test-nodeps
test-nodeps: ## Run Go tests.
	# A workaround for https://github.com/golang/go/issues/75031
	$(GO) env -w GOTOOLCHAIN=go1.25.0+auto
	$(GO) test -exec "$(SUDO)" -tags sudo_tests -p 1 -parallel 1 $(GOFLAGS) -gcflags=$(GO_BUILD_GCFLAGS) -timeout $(GO_TEST_TIMEOUT) -failfast -cover $(GO_TEST_PACKAGES) ${EXTRA_TESTFLAGS}

.PHONY: test-nodeps-lseg
test-nodeps-lseg: ## Run Go tests on LSEG build.
	# A workaround for https://github.com/golang/go/issues/75031
	$(GO) env -w GOTOOLCHAIN=go1.25.0+auto
	$(GO) test -exec "$(SUDO)" -tags sudo_tests,lseg -p 1 -parallel 1 $(GOFLAGS) -gcflags=$(GO_BUILD_GCFLAGS) -timeout $(GO_TEST_TIMEOUT) -failfast -cover $(GO_TEST_PACKAGES) ${EXTRA_TESTFLAGS}

.PHONY: tester-progs
tester-progs:
	$(MAKE) -C $(TESTER_PROGS_DIR)
	$(MAKE) -C $(OSS_TESTER_PROGS_DIR)
	# NB(kkourt): This is not pretty, but we need it so that OSS testutils can find its contrib
	# programs. We can probably refactor OSS to deal with it, but that's for another day.
	ln -s -f $(OSS_DIR)/contrib vendor/github.com/cilium/tetragon/

.PHONY: ee-tester-progs-tarball
ee-tester-progs-tarball:
	$(MAKE) -C $(TESTER_PROGS_DIR)
	tar -C $(TESTER_PROGS_DIR) -czf ee-tester-progs.tar.gz \
		--transform 's:^:ee-tester-progs/:' \
		$(shell $(MAKE) -s -C $(TESTER_PROGS_DIR) all-files)

.PHONY: tetragon-bpf-test
ifeq (1,$(LOCAL_CLANG))
tetragon-bpf-test: tetragon-bpf-test-local ## Compile BPF unit test programs.
else
tetragon-bpf-test: tetragon-bpf-test-container
endif

.PHONY: tetragon-bpf-test-local
tetragon-bpf-test-local:
	$(MAKE) -C ./bpf/tests BPF_TARGET_ARCH=$(BPF_TARGET_ARCH) -j$(JOBS) $(__BPF_DEBUG_FLAGS)

.PHONY: tetragon-bpf-test-container
tetragon-bpf-test-container:
	$(CONTAINER_ENGINE) rm tetragon-clang || true
	$(CONTAINER_ENGINE) run --rm -v $(CURDIR):/tetragon -u $$(id -u) --name tetragon-clang $(CLANG_IMAGE) $(MAKE) -C /tetragon/bpf/tests BPF_TARGET_ARCH=$(BPF_TARGET_ARCH) -j$(JOBS) $(__BPF_DEBUG_FLAGS)

## bpf-test: ## Run BPF tests.
.PHONY: bpf-test
bpf-test: tetragon-bpf-test
	$(MAKE) -C ./bpf test

.PHONY: tetragon-bpf-verify
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
	done | GOMAXPROCS=1 xargs -P $(JOBS) -I {} bash -c '$(GO) test -gcflags=$(GO_BUILD_GCFLAGS) {}'

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

.PHONY: check-helm-version
check-helm-version:
	@actual="$$(helm version --short 2>/dev/null | cut -d+ -f1)"; \
	if [ "$$actual" != "$(HELM_VERSION)" ]; then \
		echo "Helm $(HELM_VERSION) is required on PATH (found: $${actual:-not installed})" >&2; \
		exit 1; \
	fi

## e2e-test: ## run e2e tests
## e2e-test E2E_BUILD_IMAGES=0: ## run e2e tests without (re-)building images
## e2e-test E2E_TESTS=./tests/e2e/tests/helm/skeleton: ## run a specific e2e test
.PHONY: e2e-test
ifneq ($(E2E_BUILD_IMAGES), 0)
e2e-test: check-helm-version image image-operator
else
e2e-test: check-helm-version
endif
	$(GO) test -p 1 -parallel 1 $(E2E_COVER_FLAG) $(E2E_GO_BUILD_GCFLAGS)  \
		-tags e2e_tests                                                \
		-timeout $(E2E_TIMEOUT) ${E2E_EXTRA_GOTEST_FLAGS}              \
		${E2E_TESTS} ${E2E_EXTRA_TEST_FLAGS} $(E2E_BTF_FLAGS)          \
		-tetragon.helm.set tetragon.grpc.address=localhost:54321      \
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
	# Use the enterprise kind-config to support FIM
	$(MAKE) -C $(OSS_DIR) kind KIND_CONFIG=$(shell realpath ./contrib/kind/kind-config.yaml)

KIND_BUILD_IMAGES ?= 1
export TETRAGON_KIND_BASE_VALUES = ./contrib/kind/values.yaml
export TETRAGON_KIND_HELM_CHART = ./install/kubernetes/tetragon

.PHONY: build-helm-tetragon
build-helm-tetragon:
	$(MAKE) -C install/kubernetes

## kind-install-tetragon: ## Install Tetragon in a kind cluster.
## kind-install-tetragon KIND_BUILD_IMAGES=0: ## Install Tetragon in a kind cluster without (re-)building images.
## kind-install-tetragon VALUES=values.yaml: ## Install Tetragon in a kind cluster using additional Helm values.
.PHONY: kind-install-tetragon
ifneq ($(KIND_BUILD_IMAGES), 0)
kind-install-tetragon: check-helm-version image image-operator build-helm-tetragon
else
kind-install-tetragon: check-helm-version build-helm-tetragon
endif
ifneq ($(VALUES),)
	$(OSS_DIR)/contrib/kind/install-tetragon.sh -v $(VALUES) --force
else
	$(OSS_DIR)/contrib/kind/install-tetragon.sh --force
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
	# YAML CRDs also live in the helm charts, so update them as well.
	$(MAKE) -C install/kubernetes

.PHONY: depfix
depfix: ## Update go.mod to match upstream dependencies
	./contrib/build/depfix

.PHONY: vendor
vendor: depfix ## Tidy and vendor Go modules.
	$(MAKE) -C api vendor
	# Need to call vendor twice here, once before and once after generate, the reason
	# being we need to grab changes first plus pull in whatever gets generated here.
	$(MAKE) -C pkg/k8s vendor
	$(MAKE) -C pkg/k8s
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
		$(CONTAINER_ENGINE) run --user $(shell id -u):$(shell id -g) -v $(shell realpath .):/fgs "isovalent/clang-format:${DOCKER_IMAGE_TAG}" -i -style=file
endif

.PHONY: go-format
go-format: ## Run code formatter on Go code.
	$(GOLANGCILINT_BIN) fmt
	$(GOLANGCILINT_BIN) run --fix --enable-only wsl_v5

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
	$(CONTAINER_ENGINE) run --rm -v $(CURDIR):$(CURDIR) -w $(CURDIR) $(GO_IMAGE) ./tetragon-metrics-docs health >> $(METRICS_DOCS_PATH)
	$(CONTAINER_ENGINE) run --rm -v $(CURDIR):$(CURDIR) -w $(CURDIR) $(GO_IMAGE) ./tetragon-metrics-docs resources >> $(METRICS_DOCS_PATH)
	$(CONTAINER_ENGINE) run --rm -v $(CURDIR):$(CURDIR) -w $(CURDIR) $(GO_IMAGE) ./tetragon-metrics-docs health-dns >> $(METRICS_DOCS_PATH)
	$(CONTAINER_ENGINE) run --rm -v $(CURDIR):$(CURDIR) -w $(CURDIR) $(GO_IMAGE) ./tetragon-metrics-docs health-file >> $(METRICS_DOCS_PATH)
	$(CONTAINER_ENGINE) run --rm -v $(CURDIR):$(CURDIR) -w $(CURDIR) $(GO_IMAGE) ./tetragon-metrics-docs health-http >> $(METRICS_DOCS_PATH)
	$(CONTAINER_ENGINE) run --rm -v $(CURDIR):$(CURDIR) -w $(CURDIR) $(GO_IMAGE) ./tetragon-metrics-docs health-network >> $(METRICS_DOCS_PATH)
	$(CONTAINER_ENGINE) run --rm -v $(CURDIR):$(CURDIR) -w $(CURDIR) $(GO_IMAGE) ./tetragon-metrics-docs health-tls >> $(METRICS_DOCS_PATH)
	$(CONTAINER_ENGINE) run --rm -v $(CURDIR):$(CURDIR) -w $(CURDIR) $(GO_IMAGE) ./tetragon-metrics-docs events >> $(METRICS_DOCS_PATH)
	$(CONTAINER_ENGINE) run --rm -v $(CURDIR):$(CURDIR) -w $(CURDIR) $(GO_IMAGE) ./tetragon-metrics-docs dns >> $(METRICS_DOCS_PATH)
	$(CONTAINER_ENGINE) run --rm -v $(CURDIR):$(CURDIR) -w $(CURDIR) $(GO_IMAGE) ./tetragon-metrics-docs file >> $(METRICS_DOCS_PATH)
	$(CONTAINER_ENGINE) run --rm -v $(CURDIR):$(CURDIR) -w $(CURDIR) $(GO_IMAGE) ./tetragon-metrics-docs http >> $(METRICS_DOCS_PATH)
	$(CONTAINER_ENGINE) run --rm -v $(CURDIR):$(CURDIR) -w $(CURDIR) $(GO_IMAGE) ./tetragon-metrics-docs icmp >> $(METRICS_DOCS_PATH)
	$(CONTAINER_ENGINE) run --rm -v $(CURDIR):$(CURDIR) -w $(CURDIR) $(GO_IMAGE) ./tetragon-metrics-docs interface >> $(METRICS_DOCS_PATH)
	$(CONTAINER_ENGINE) run --rm -v $(CURDIR):$(CURDIR) -w $(CURDIR) $(GO_IMAGE) ./tetragon-metrics-docs network >> $(METRICS_DOCS_PATH)
	$(CONTAINER_ENGINE) run --rm -v $(CURDIR):$(CURDIR) -w $(CURDIR) $(GO_IMAGE) ./tetragon-metrics-docs tcp >> $(METRICS_DOCS_PATH)
	$(CONTAINER_ENGINE) run --rm -v $(CURDIR):$(CURDIR) -w $(CURDIR) $(GO_IMAGE) ./tetragon-metrics-docs udp >> $(METRICS_DOCS_PATH)
	$(CONTAINER_ENGINE) run --rm -v $(CURDIR):$(CURDIR) -w $(CURDIR) $(GO_IMAGE) ./tetragon-metrics-docs rawsocket >> $(METRICS_DOCS_PATH)
	$(CONTAINER_ENGINE) run --rm -v $(CURDIR):$(CURDIR) -w $(CURDIR) $(GO_IMAGE) ./tetragon-metrics-docs tls >> $(METRICS_DOCS_PATH)
	$(CONTAINER_ENGINE) run --rm -v $(CURDIR):$(CURDIR) -w $(CURDIR) $(GO_IMAGE) ./tetragon-metrics-docs debug-dns-parser >> $(METRICS_DOCS_PATH)
	$(CONTAINER_ENGINE) run --rm -v $(CURDIR):$(CURDIR) -w $(CURDIR) $(GO_IMAGE) ./tetragon-metrics-docs alerts >> $(METRICS_DOCS_PATH)
	$(CONTAINER_ENGINE) run --rm -v $(CURDIR):$(CURDIR) -w $(CURDIR) $(GO_IMAGE) ./tetragon-metrics-docs appmodel >> $(METRICS_DOCS_PATH)

.PHONY: gen-docs-references
gen-docs-references: generate-flags metrics-docs ## Convenience alias to generate all docs references.

.PHONY: validate
validate: check format generate-flags metrics-docs ## Convenience target running linters, formatters and generators across the codebase.
	# FIXME: add api linting once we fix the lints
	$(MAKE) -C api vendor format proto
	$(MAKE) -C pkg/k8s vendor generate
	# Vendoring includes api and pkg/k8s vendoring. To avoid running vendor
	# million times, run the global vendor target after api and pkg/k8s builds.
	$(MAKE) vendor
	$(MAKE) -C install/kubernetes
	$(MAKE) -C install/kubernetes validation

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

.PHONY: checkpatch
# renovate: datasource=docker
CHECKPATCH_IMAGE := quay.io/cilium/cilium-checkpatch:1755701578-b97bd7a@sha256:f1332fa6edbbd40882a59ceae4a7843a4095bd62288363740e84b82708624c50
CHECKPATCH_IGNORE := --ignore PREFER_DEFINED_ATTRIBUTE_MACRO,C99_COMMENTS,OPEN_ENDED_LINE,PREFER_KERNEL_TYPES,REPEATED_WORD,SPDX_LICENSE_TAG,LONG_LINE,LONG_LINE_STRING,LONG_LINE_COMMENT,TRACE_PRINTK,AVOID_EXTERNS
ifneq ($(CHECKPATCH_DEBUG),)
  # Run script with "bash -x"
  CHECKPATCH_IMAGE_AND_ENTRY := \
	--entrypoint /bin/bash $(CHECKPATCH_IMAGE) -x /checkpatch/checkpatch.sh -- $(CHECKPATCH_IGNORE)
else
  # Use default entrypoint
  CHECKPATCH_IMAGE_AND_ENTRY := \
	--entrypoint /bin/bash $(CHECKPATCH_IMAGE) /checkpatch/checkpatch.sh -- $(CHECKPATCH_IGNORE)
endif
checkpatch: ## Run checkpatch on your current branch commits.
	$(QUIET) $(CONTAINER_ENGINE) container run --rm \
		--workdir /workspace \
		--volume $(CURDIR):/workspace \
		--user "$(shell id -u):$(shell id -g)" \
		-e GITHUB_REF=$(GITHUB_REF) -e GITHUB_REPOSITORY=$(GITHUB_REPOSITORY) -e GITHUB_TOKEN=$(GITHUB_TOKEN) \
		$(CHECKPATCH_IMAGE_AND_ENTRY) $(CHECKPATCH_ARGS)

##@ OSS submodule helpers

## oss-sync: ## Sync OSS submodule with the main branch and create an oss-sync commit.
## oss-sync OSS_SYNC_TARGET=pr/lambdanis/fix-bug: ## Sync OSS submodule with a specific branch.
.PHONY: oss-sync
oss-sync:
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

$(OSS_DIR)/Makefile.defs:
	test -e $(OSS_DIR)/Makefile.defs || git submodule update --init $(OSS_DIR)

include $(OSS_DIR)/Makefile.defs

.PHONY: help
help:  ## Display this help, based on https://www.thapaliya.com/en/writings/well-documented-makefiles/
	$(call print_help_from_comments)

.PHONY: version chart-version
version: ## Print Tetragon version.
	@echo $(VERSION)

.PHONY: hs-version
hs-version: ## Compute version/date/sha for build-images workflows; writes to $GITHUB_OUTPUT when set.
	@bash -euo pipefail -c ' \
		VERSION=$$($(MAKE) -s --no-print-directory version); \
		echo "Version from make: $$VERSION"; \
		if [[ -z "$$VERSION" || "$$VERSION" =~ ^[a-f0-9]{7,}$$ ]]; then \
			echo "WARNING: Version appears to be empty or a SHA. Using tag from git describe instead."; \
			VERSION=$$(git describe --tags --abbrev=0 --exclude "api/*" --exclude "*-codedrop" 2>/dev/null || echo "v0.0.0"); \
			echo "Updated version to: $$VERSION"; \
		fi; \
		if [[ "$$VERSION" == api/* ]]; then \
			VERSION="$${VERSION#api/}"; \
			echo "Stripped api/ prefix, updated version: $$VERSION"; \
		fi; \
		VERSION=$$(echo "$$VERSION" | sed -E "s/-g[0-9a-f]+$$//"); \
		DATE=$$(date -u +"%Y%m%d%H%M"); \
		SHA=$$(git rev-parse --short HEAD); \
		GITHUB_OUTPUT_FILE="$${GITHUB_OUTPUT:-}"; \
		if [[ -n "$$GITHUB_OUTPUT_FILE" ]]; then \
			echo "version=$$VERSION" >> "$$GITHUB_OUTPUT_FILE"; \
			echo "date=$$DATE" >> "$$GITHUB_OUTPUT_FILE"; \
			echo "sha=$$SHA" >> "$$GITHUB_OUTPUT_FILE"; \
		else \
			echo "version=$$VERSION"; \
			echo "date=$$DATE"; \
			echo "sha=$$SHA"; \
		fi'

.PHONY: validate-release-metadata
validate-release-metadata: ## Validate REL_VERSION, REL_DATE, REL_SHA inputs used by build-images workflows.
	@bash -euo pipefail -c ' \
		VERSION="$${REL_VERSION:-}"; \
		DATE="$${REL_DATE:-}"; \
		SHA="$${REL_SHA:-}"; \
		echo "=== Release Metadata Validation ==="; \
		echo "Version: $$VERSION"; \
		echo "Date: $$DATE"; \
		echo "SHA: $$SHA"; \
		echo "==================================="; \
		ERRORS=0; \
		if [[ -z "$$VERSION" ]]; then \
			echo "::error::VERSION is empty - release metadata validation failed"; \
			ERRORS=$$((ERRORS + 1)); \
		fi; \
		if [[ -z "$$DATE" ]]; then \
			echo "::error::DATE is empty - release metadata validation failed"; \
			ERRORS=$$((ERRORS + 1)); \
		fi; \
		if [[ -z "$$SHA" ]]; then \
			echo "::error::SHA is empty - release metadata validation failed"; \
			ERRORS=$$((ERRORS + 1)); \
		fi; \
		if [[ -n "$$SHA" && ! "$$SHA" =~ ^[a-f0-9]{7,}$$ ]]; then \
			echo "::error::SHA format invalid (expected 7+ hex chars): $$SHA"; \
			ERRORS=$$((ERRORS + 1)); \
		fi; \
		if [[ -n "$$DATE" && ! "$$DATE" =~ ^[0-9]{12}$$ ]]; then \
			echo "::error::DATE format invalid (expected YYYYMMDDHHMM): $$DATE"; \
			ERRORS=$$((ERRORS + 1)); \
		fi; \
		if [[ $$ERRORS -gt 0 ]]; then \
			echo "::error::Release metadata validation failed with $$ERRORS error(s)"; \
			exit 1; \
		fi; \
		echo "✓ All release metadata validated successfully"'

.PHONY: release-artifacts-verify-checksums
release-artifacts-verify-checksums: ## Verify checksums in REL_DIR using REL_SUMS_FILE (default: SHA256SUMS.txt).
	@bash -euo pipefail -c ' \
		REL_DIR="$${REL_DIR:-./release-artifacts}"; \
		REL_SUMS_FILE="$${REL_SUMS_FILE:-SHA256SUMS.txt}"; \
		cd "$$REL_DIR"; \
		echo "=== Verifying SHA256 checksums ==="; \
		if ! sha256sum -c "$$REL_SUMS_FILE"; then \
			echo "::error::Checksum verification failed"; \
			exit 1; \
		fi; \
		echo "✓ All checksums verified successfully"'

.PHONY: release-artifacts-validate-files
release-artifacts-validate-files: ## Ensure required files exist in REL_DIR (REL_REQUIRED_FILES is newline-separated).
	@bash -euo pipefail -c ' \
		REL_DIR="$${REL_DIR:-./release-artifacts}"; \
		REL_REQUIRED_FILES="$${REL_REQUIRED_FILES:-}"; \
		ERRORS=0; \
		while IFS= read -r file; do \
			if [[ -z "$$file" ]]; then \
				continue; \
			fi; \
			if [[ ! -f "$$REL_DIR/$$file" ]]; then \
				echo "::error::Required artifact missing: $$file"; \
				ERRORS=$$((ERRORS + 1)); \
			fi; \
		done <<< "$$REL_REQUIRED_FILES"; \
		if [[ $$ERRORS -gt 0 ]]; then \
			exit 1; \
		fi; \
		echo "✓ All required artifacts present"'

chart-version: ## Print Tetragon OCI Helm chart version.
	@echo $(VERSION) | sed 's/^v\(.*\)/\1/'
