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

BUILD_PKG_DIR ?= $(shell pwd)/build/$(TARGET_ARCH)
LIBBPF_INSTALL_DIR ?= ./lib
VERSION=$(shell git describe --tags --always --exclude 'api/*')

OSS_DIR=./modules/tetragon-oss
FS_SCANNER_BIN=bpf/objs/hubble-fgs-fs-scanner
FS_SCANNER_RUNNER=bpf/objs/hubble-fgs-runner 

# Directories to enforce copyright headers on
COPYRIGHT_DIRS = pkg/bench cmd/fgs-bench bpf/parsers/http

TESTER_PROGS_DIR = "contrib/tester-progs"

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

# Branch in the OSS repo we want to sync with. Default is origin/main
OSS_SYNC_TARGET ?= origin/main

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

-include Makefile.docker
-include Makefile.cli

.PHONY: help
help:
	@echo 'OSS submodule helpers: '
	@echo '    oss-sync     - sync OSS submodule and create an oss-sync commit'
	@echo '    oss-init     - initialize the OSS submodule'
	@echo '    oss-checkout - pull in OSS code that matches the current registered version and update everything (codegen, go modules)'
	@echo '    oss-update   - pull in latest OSS code and update everything (codegen, go modules)'
	@echo 'Generated files: '
	@echo '    codegen      - genereate code based on .proto files'
	@echo '    generate     - genereate kubebuilder files'
	@echo 'Compilation: '
	@echo '    tetragon          - compile the Tetragon agent'
	@echo '    tetragon-operator - compile the Tetragon operator'
	@echo '    tetra             - compile the Tetragon gRPC client'
	@echo '    tetragon-bpf      - compile bpf programs'
	@echo '    test-compile - compile go tests'
	@echo 'Packages:'
	@echo '    tarball           - build Tetragon Enterprise compressed tarball'
	@echo '    tarball-release   - build Tetragon Enterprise release tarball'
	@echo 'Helpers: '
	@echo '    version     - retrieve the current git tag version of the project'

.PHONY: oss-sync
oss-sync:
	@echo Syncing OSS submodule...
	@./contrib/oss-chores/oss-sync.sh "$(OSS_SYNC_TARGET)"

.PHONY: oss-init
oss-init:
	@echo Initializing and updating submodules...
	git submodule update --init $(OSS_DIR)

.PHONY: oss-update
oss-update:
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

.PHONY: oss-checkout
oss-checkout:
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

# Generate compile-commands.json using bear
.PHONY: compile-commands
compile-commands:
	$(MAKE) -C ./bpf clean
	bear -- $(MAKE) -C ./bpf

.PHONY: tetragon-bpf
ifeq (1,$(LOCAL_CLANG))
tetragon-bpf: tetragon-bpf-local
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

.PHONY: tetragon-bpf-verify
tetragon-bpf-verify: tetragon-bpf
	sudo contrib/fgs-verify-programs bpf/objs

.PHONY: tetragon
tetragon: hubble-fgs-fs-scanner
	$(GO_BUILD) ./cmd/tetragon

.PHONY: tetra
tetra:
	$(GO_BUILD) ./cmd/tetra

.PHONY: tetragon-operator
tetragon-operator:
	$(GO_BUILD) -o $@ ./operator

.PHONY: hubble-fgs-fs-scanner
hubble-fgs-fs-scanner:
	$(GO_BUILD) -buildvcs=false -o $(FS_SCANNER_BIN) ./cmd/hubble-fgs-fs-scanner/
	$(CC) -static -Wall -Wextra -o $(FS_SCANNER_RUNNER) contrib/fs-scanner-runner/hubble-fgs-runner.c

.PHONY: ksyms
ksyms:
	make -C $(OSS_DIR) ksyms
	cp $(OSS_DIR)/ksyms ksyms

install:
	groupadd -f hubble
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 ./hubble-fgs $(DESTDIR)$(BINDIR)

.PHONY: vendor
vendor:
	$(MAKE) -C ./api vendor
	$(MAKE) -C ./pkg/k8s vendor
	$(GO) mod tidy
	$(GO) mod vendor
	$(GO) mod verify

.PHONY: clean
clean: tarball-clean
	$(MAKE) -C ./bpf clean
	$(MAKE) -C $(TESTER_PROGS_DIR) clean
	rm -f go-tests/*.test ./ksyms ./tetra ./tetragon-operator ./tetragon ./fgs-alignchecker ./fgs-bench $(FS_SCANNER_BIN)
	rm -fr ./release

.PHONY: fgs-bench
fgs-bench:
	$(GO) build ./cmd/fgs-bench

.PHONY: fgs-bench-image
fgs-bench-image:
	$(GO_BUILD) ./cmd/fgs-bench

.PHONY: fgs-bench-graph
fgs-bench-graph:
	$(GO) build ./cmd/fgs-bench-graph

.PHONY: parsertest
parsertest:
	$(GO) test -c ./pkg/parsertest -o parsertest

.PHONY: parsertest-gen
parsertest-gen:
	$(GO_BUILD) ./cmd/parsertest-gen

.PHONY: alignchecker
alignchecker:
	$(GO) test -c ./pkg/alignchecker -o alignchecker

package-fgs-bench: hubble-bpf-local fgs-bench
	tar --transform="s|^|fgs-bench/|" \
	    -czhf fgs-bench.tar.gz bpf/objs/*.o fgs-bench

.PHONY: test
test: tester-progs hubble-bpf
	$(SUDO) $(GO) test -p 1 -parallel 1 $(GOFLAGS) -gcflags=$(GO_BUILD_GCFLAGS) -timeout $(GO_TEST_TIMEOUT) -failfast -cover ./pkg/... ./cmd/... ${EXTRA_TESTFLAGS}

E2E_TIMEOUT ?= 20m
# Agent image to use for end-to-end tests
E2E_AGENT ?= isovalent/hubble-fgs:$(DOCKER_IMAGE_TAG)
# Operator image to use for end-to-end tests
E2E_OPERATOR ?= isovalent/hubble-enterprise-operator:$(DOCKER_IMAGE_TAG)
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
E2E_TESTS ?= ./tests/e2e/tests/...

# Run an e2e-test
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

TEST_COMPILE ?= ./...
.PHONY: test-compile
test-compile:
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


.PHONY: check-copyright update-copyright
check-copyright:
	for dir in $(COPYRIGHT_DIRS); do \
		contrib/copyright-headers check $$dir; \
	done

update-copyright:
	for dir in $(COPYRIGHT_DIRS); do \
		contrib/copyright-headers update $$dir; \
	done

lint:
	golint -set_exit_status $$(go list ./...)

.PHONY: tarball
# Share same build environment as docker image
tarball: tarball-clean image
	$(CONTAINER_ENGINE) build --build-arg TETRAGON_VERSION=$(VERSION) --build-arg TARGET_ARCH=$(TARGET_ARCH) -f Dockerfile.tarball -t "isovalent/tetragon-tarball:${DOCKER_IMAGE_TAG}" --platform=linux/${TARGET_ARCH} .
	$(QUIET)mkdir -p $(BUILD_PKG_DIR)
	$(CONTAINER_ENGINE) save isovalent/tetragon-tarball:$(DOCKER_IMAGE_TAG) -o $(BUILD_PKG_DIR)/tetragon-ee-$(VERSION)-$(TARGET_ARCH).tmp.tar
	$(QUIET)rm -fr $(BUILD_PKG_DIR)/docker/
	$(QUIET)mkdir -p $(BUILD_PKG_DIR)/docker/
	$(QUIET)rm -fr $(BUILD_PKG_DIR)/linux-tarball/
	$(QUIET)mkdir -p $(BUILD_PKG_DIR)/linux-tarball/
	tar xC $(BUILD_PKG_DIR)/docker/ -f $(BUILD_PKG_DIR)/tetragon-ee-$(VERSION)-$(TARGET_ARCH).tmp.tar
	find $(BUILD_PKG_DIR)/docker/ -name 'layer.tar' -exec cp '{}' $(BUILD_PKG_DIR)/linux-tarball/tetragon-ee-$(VERSION)-$(TARGET_ARCH).tar \;
	@rm -fr $(BUILD_PKG_DIR)/tetragon-ee-$(VERSION)-$(TARGET_ARCH).tmp.tar
	gzip -6 $(BUILD_PKG_DIR)/linux-tarball/tetragon-ee-$(VERSION)-$(TARGET_ARCH).tar
	@echo "tetragon tarball is ready: $(BUILD_PKG_DIR)/linux-tarball/tetragon-ee-$(VERSION)-$(TARGET_ARCH).tar.gz"

.PHONY: tarball-release
tarball-release: tarball
	mkdir -p release/
	mv $(BUILD_PKG_DIR)/linux-tarball/tetragon-ee-$(VERSION)-$(TARGET_ARCH).tar.gz release/
	(cd release && sha256sum tetragon-ee-$(VERSION)-$(TARGET_ARCH).tar.gz > tetragon-ee-$(VERSION)-$(TARGET_ARCH).tar.gz.sha256sum)

.PHONY: tarball-clean
tarball-clean:
	rm -fr $(BUILD_PKG_DIR)

.PHONY: image
image:
	$(CONTAINER_ENGINE) build -t "${TETRAGON_IMAGE_NAME}:${DOCKER_IMAGE_TAG}" --target release --platform=linux/${TARGET_ARCH} .
	$(QUIET)@echo "Push like this when ready:"
	$(QUIET)@echo "${CONTAINER_ENGINE} push ${IMAGE_NAME}:$(DOCKER_IMAGE_TAG)"

.PHONY: image-operator
image-operator:
	$(CONTAINER_ENGINE) build -f Dockerfile.operator -t "${OPERATOR_IMAGE_NAME}:${DOCKER_IMAGE_TAG}" --platform=linux/${TARGET_ARCH} .
	$(QUIET)@echo "Push like this when ready:"
	$(QUIET)@echo "${CONTAINER_ENGINE} push ${OPERATOR_IMAGE_NAME}:$(DOCKER_IMAGE_TAG)"

image-test:
	$(CONTAINER_ENGINE) build -f Dockerfile.test -t "isovalent/hubble-fgs-test:${DOCKER_IMAGE_TAG}" .
	$(QUIET)@echo "Push like this when ready:"
	$(QUIET)@echo "${CONTAINER_ENGINE} push isovalent/hubble-fgs-test:$(DOCKER_IMAGE_TAG)"

image-codegen:
	$(CONTAINER_ENGINE) build -f Dockerfile.codegen -t "isovalent/tetragon-codegen:${DOCKER_IMAGE_TAG}" .
	$(QUIET)@echo "Push like this when ready:"
	$(QUIET)@echo "${CONTAINER_ENGINE} push isovalent/tetragon-codegen:$(DOCKER_IMAGE_TAG)"

.PHONY: image-clang
image-clang:
	$(CONTAINER_ENGINE) build -f Dockerfile.clang -t "cilium/clang:${DOCKER_IMAGE_TAG}" .
	$(QUIET)@echo "Push like this when ready:"
	$(QUIET)@echo "${CONTAINER_ENGINE} push cilium/clang:$(DOCKER_IMAGE_TAG)"

fetch-testdata:
	docker stop fgs-md-temp || true
	docker rm fgs-md-temp || true
	docker create --name fgs-md-temp $(METADATA_IMAGE)
	mkdir -p testdata/btf
	docker cp fgs-md-temp:/var/run/tetragon-ee-metadata/vmlinux-5.4.104+ testdata/btf
	docker stop fgs-md-temp || true

generate:
	# Need to call vendor twice here, once before and once after generate, the reason
	# being we need to grab changes first plus pull in whatever gets generated here.
	$(MAKE) vendor
	$(MAKE) -C pkg/k8s
	$(MAKE) vendor

codegen: image-codegen
	# Need to call vendor twice here, once before and once after codegen the reason
	# being we need to grab changes first plus pull in whatever gets generated here.
	$(MAKE) vendor
	$(MAKE) -C api
	$(MAKE) vendor

# renovate: datasource=docker
GOLANGCILINT_IMAGE=docker.io/golangci/golangci-lint:v1.55.2@sha256:e699df940be1810b08ba6ec050bfc34cc1931027283b5a7f607fb6a67b503876
GOLANGCILINT_WANT_VERSION := $(subst @sha256,,$(patsubst v%,%,$(word 2,$(subst :, ,$(lastword $(subst /, ,$(GOLANGCILINT_IMAGE)))))))
GOLANGCILINT_VERSION = $(shell golangci-lint version 2>/dev/null)
ifneq (,$(findstring $(GOLANGCILINT_WANT_VERSION),$(GOLANGCILINT_VERSION)))
check:
	golangci-lint run
else
check:
	docker run --rm -v `pwd`:/app -w /app --env GOTOOLCHAIN=auto $(GOLANGCILINT_IMAGE) golangci-lint run
endif

.PHONY: clang-format
ifeq (1,$(LOCAL_CLANG_FORMAT))
clang-format:
	find bpf $(FORMAT_FIND_FLAGS) | xargs -n 1000 clang-format -i -style=file
else
clang-format:
	$(CONTAINER_ENGINE) build -f Dockerfile.clang-format -t "isovalent/clang-format:${DOCKER_IMAGE_TAG}" .
	find bpf $(FORMAT_FIND_FLAGS) | xargs -n 1000 \
		$(CONTAINER_ENGINE) run -v $(shell realpath .):/fgs "isovalent/clang-format:${DOCKER_IMAGE_TAG}" -i -style=file
endif

.PHONY: go-format
go-format:
	find . -name '*.go' -not -path './vendor/*' -not -path './api/vendor/*' -not -path './pkg/k8s/vendor/*' -not -path './modules/*' -not -path './api/v1/tetragon/*' | xargs gofmt -w

.PHONY: format
format: go-format clang-format

.PHONY: headers image install lint generate check


# generate cscope for bpf files
cscope:
	find bpf -name "*.[chxsS]" -print > cscope.files
	cscope -b -q -k
.PHONY: cscope

tester-progs:
	$(MAKE) -C $(TESTER_PROGS_DIR)
.PHONY: tester-progs

version:
	@echo $(VERSION)
.PHONY: version

# those are legacy aliases
.PHONY: hubble-fgs
hubble-fgs: tetragon
.PHONY: hubble-enterprise
hubble-enterprise: tetra
.PHONY: hubble-enterprise-operator
hubble-enterprise-operator: tetragon-operator
.PHONY: hubble-bpf
hubble-bpf: tetragon-bpf
.PHONY: hubble-bpf-verify
hubble-bpf-verify: tetragon-bpf-verify

