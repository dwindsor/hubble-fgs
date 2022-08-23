GO := go
INSTALL = $(QUIET)install
BINDIR ?= /usr/local/bin
CONTAINER_ENGINE ?= docker
DOCKER_IMAGE_TAG ?= latest
LOCAL_CLANG ?= 0
LOCAL_CLANG_FORMAT ?= 0
FORMAT_FIND_FLAGS ?= -name '*.c' -o -name '*.h' -not -path 'bpf/include/vmlinux.h' -not -path 'bpf/include/api.h' -not -path 'bpf/libbpf/*'
NOOPT ?= 0
CLANG_IMAGE = quay.io/cilium/clang:7ea8dd5b610a8864ce7b56e10ffeb61030a0c50e@sha256:02ad7cc1d08d85c027557099b88856945be5124b5c31aeabce326e7983e3913b
METADATA_IMAGE = quay.io/isovalent/hubble-enterprise-metadata
# Extra flags to pass to test binary
EXTRA_TESTFLAGS ?=

LIBBPF_INSTALL_DIR ?= ./lib
VERSION=$(shell git describe --tags --always)
GO_GCFLAGS ?= ""
GO_LDFLAGS="-X 'github.com/isovalent/hubble-fgs/pkg/version.Version=$(VERSION)'"
GO_IMAGE_LDFLAGS="-X 'github.com/isovalent/hubble-fgs/pkg/version.Version=$(VERSION)' -linkmode external -extldflags -static"
GO_OPERATOR_IMAGE_LDFLAGS="-X 'github.com/isovalent/hubble-fgs/pkg/version.Version=$(VERSION)' -s -w"

OSS_DIR=./modules/tetragon-oss

KATA_RUNNER = docker run --runtime=kata-runtime --cap-add all --ulimit memlock=-1:-1 -v /var/lib/kata-containers/images/btf:/var/lib/hubble-fgs/btf -v $(CURDIR):/go/src/github.com/isovalent/hubble-fgs -v /proc:/procRoot isovalent/hubble-fgs-test

GOLANGCILINT_WANT_VERSION = 1.48.0
GOLANGCILINT_VERSION = $(shell golangci-lint version 2>/dev/null)

# Directories to enforce copyright headers on
COPYRIGHT_DIRS = pkg/bench cmd/fgs-bench bpf/parsers/http

TESTER_PROGS_DIR = "contrib/tester-progs"

all: hubble-bpf hubble-fgs hubble-enterprise fgs-bench fgs-alignchecker test-compile tester-progs

.PHONY: hubble-bpf hubble-bpf-local hubble-bpf-container

-include Makefile.docker

.PHONY: help
help:
	@echo 'OSS submodule helpers: '
	@echo '    oss-init     - initialize the OSS submodule'
	@echo '    oss-checkout - pull in OSS code that matches the current registered version and update everything (codegen, go modules)'
	@echo '    oss-update   - pull in latest OSS code and update everything (codegen, go modules)'
	@echo 'Generated files: '
	@echo '    codegen      - genereate code based on .proto files'
	@echo '    generate     - genereate kubebuilder files'
	@echo 'Compilation: '
	@echo '    test-compile - compile go tests'

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

ifeq (1,$(LOCAL_CLANG))
hubble-bpf: hubble-bpf-local
else
hubble-bpf: hubble-bpf-container
endif

ifeq (1,$(NOOPT))
GO_GCFLAGS = "all=-N -l"
endif

hubble-bpf-local:
	$(MAKE) -C ./bpf

hubble-bpf-verify: hubble-bpf
	sudo contrib/vmtest/fgs-verify-programs bpf/objs

hubble-bpf-container:
	$(CONTAINER_ENGINE) rm hubble-clang || true
	$(CONTAINER_ENGINE) run -v $(CURDIR):/hubble-fgs -u $$(id -u) --name hubble-clang $(CLANG_IMAGE) $(MAKE) -C /hubble-fgs/bpf
	$(CONTAINER_ENGINE) rm hubble-clang

hubble-fgs:
	$(GO) build -tags enterprise -gcflags=$(GO_GCFLAGS) -ldflags=$(GO_LDFLAGS) -mod=vendor ./cmd/hubble-fgs/

hubble-enterprise:
	$(GO) build -gcflags=$(GO_GCFLAGS) -ldflags=$(GO_LDFLAGS) -mod=vendor ./cmd/hubble-enterprise/

hubble-enterprise-operator:
	$(GO) build -gcflags=$(GO_GCFLAGS) -ldflags=$(GO_LDFLAGS) -mod=vendor -o $@ ./operator

fgs-alignchecker:
	make -C $(OSS_DIR) tetragon-alignchecker
	cp $(OSS_DIR)/tetragon-alignchecker fgs-alignchecker

.PHONY: ksyms
ksyms:
	make -C $(OSS_DIR) ksyms
	cp $(OSS_DIR)/ksyms ksyms

hubble-fgs-image:
	GOOS=linux GOARCH=amd64 $(GO) build -tags enterprise,netgo -mod=vendor -ldflags=$(GO_IMAGE_LDFLAGS) ./cmd/hubble-fgs/
	GOOS=linux GOARCH=amd64 $(GO) build -tags enterprise,netgo -mod=vendor -ldflags=$(GO_IMAGE_LDFLAGS) ./cmd/hubble-enterprise/

hubble-enterprise-operator-image:
	CGO_ENABLED=0 $(GO) build -ldflags=$(GO_OPERATOR_IMAGE_LDFLAGS) -mod=vendor -o hubble-enterprise-operator ./operator

install:
	groupadd -f hubble
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 ./hubble-fgs $(DESTDIR)$(BINDIR)

.PHONY: vendor
vendor:
	$(MAKE) -C ./api vendor
	$(MAKE) -C ./pkg/k8s vendor
	$(GO) mod tidy -compat=1.17
	$(GO) mod vendor
	$(GO) mod verify

clean:
	$(MAKE) -C ./bpf clean
	$(MAKE) -C $(TESTER_PROGS_DIR) clean
	rm -f go-tests/*.test ./ksyms ./hubble-enterprise ./hubble-enterprise-operator ./hubble-fgs ./fgs-alignchecker ./fgs-bench

.PHONY: fgs-bench fgs-bench-image
fgs-bench:
	$(GO) build -tags enterprise ./cmd/fgs-bench

fgs-bench-image:
	GOOS=linux GOARCH=amd64 $(GO) build -mod=vendor -ldflags=$(GO_IMAGE_LDFLAGS) ./cmd/fgs-bench

parsertest-image:
	GOOS=linux GOARCH=amd64 $(GO) test -mod=vendor -ldflags=$(GO_IMAGE_LDFLAGS) -c ./pkg/parsertest -o parsertest

package-fgs-bench: hubble-bpf-local fgs-bench
	tar --transform="s|^|fgs-bench/|" \
	    -czhf fgs-bench.tar.gz bpf/objs/*.o fgs-bench

.PHONY: test
test:
	$(GO) test -p 1 -parallel 1 $(GOFLAGS) -gcflags=$(GO_GCFLAGS) -timeout 20m -failfast -cover ./pkg/... ${EXTRA_TESTFLAGS}

.PHONY: e2e-test
e2e-test: image image-operator
	$(GO) test -p 1 -parallel 1 $(GOFLAGS) -gcflags=$(GO_GCFLAGS) -timeout 20m -failfast -cover ./tests/e2e/tests/... ${EXTRA_TESTFLAGS} -fail-fast -tetragon.helm.set enterprise.image.override="isovalent/hubble-fgs:${DOCKER_IMAGE_TAG}" -tetragon.helm.set hubbleEnterpriseOperator.image.override="isovalent/hubble-enterprise-operator:${DOCKER_IMAGE_TAG}"

TEST_COMPILE ?= ./...
.PHONY: test-compile
test-compile:
	mkdir -p go-tests
	for pkg in $$($(GO) list "$(TEST_COMPILE)"); do \
		localpkg=$$(echo $$pkg | sed -e 's:github.com/isovalent/hubble-fgs/::'); \
		localtestfile=$$(echo $$localpkg | sed -e 's:/:.:g'); \
		echo -c ./$$localpkg -o go-tests/$$localtestfile; \
	done | xargs -P $$(nproc) -L 1 $(GO) test -gcflags=$(GO_GCFLAGS)

test-kernels:
	#kata-img  vmlinuz-kata-linux-4.14.184-79_hubble
	#${KATA_RUNNER}
	kata-img vmlinuz-kata-linux-4.19.133-81_hubble
	${KATA_RUNNER}
	kata-img vmlinuz-kata-linux-5.4.51-83_hubble
	${KATA_RUNNER}


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

image:
	$(CONTAINER_ENGINE) build -t "isovalent/hubble-fgs:${DOCKER_IMAGE_TAG}" .
	$(QUIET)echo "Push like this when ready:"
	$(QUIET)echo "${CONTAINER_ENGINE} push isovalent/hubble-fgs:$(DOCKER_IMAGE_TAG)"

image-operator:
	$(CONTAINER_ENGINE) build -f operator.Dockerfile -t "isovalent/hubble-enterprise-operator:${DOCKER_IMAGE_TAG}" .
	$(QUIET)echo "Push like this when ready:"
	$(QUIET)echo "${CONTAINER_ENGINE} push isovalent/hubble-enterprise-operator:$(DOCKER_IMAGE_TAG)"

image-test:
	$(CONTAINER_ENGINE) build -f Dockerfile.test -t "isovalent/hubble-fgs-test:${DOCKER_IMAGE_TAG}" .
	$(QUIET)echo "Push like this when ready:"
	$(QUIET)echo "${CONTAINER_ENGINE} push isovalent/hubble-fgs-test:$(DOCKER_IMAGE_TAG)"

image-codegen:
	$(CONTAINER_ENGINE) build -f Dockerfile.codegen -t "isovalent/tetragon-codegen:${DOCKER_IMAGE_TAG}" .
	$(QUIET)echo "Push like this when ready:"
	$(QUIET)echo "${CONTAINER_ENGINE} push isovalent/tetragon-codegen:$(DOCKER_IMAGE_TAG)"

.PHONY: image-clang
image-clang:
	$(CONTAINER_ENGINE) build -f Dockerfile.clang -t "cilium/clang:${DOCKER_IMAGE_TAG}" .
	$(QUIET)echo "Push like this when ready:"
	$(QUIET)echo "${CONTAINER_ENGINE} push cilium/clang:$(DOCKER_IMAGE_TAG)"

fetch-testdata:
	docker stop fgs-md-temp || true
	docker rm fgs-md-temp || true
	docker create --name fgs-md-temp $(METADATA_IMAGE)
	mkdir -p testdata/btf
	docker cp fgs-md-temp:/var/run/hubble-fgs/vmlinux-5.4.104+ testdata/btf
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

ifneq (,$(findstring $(GOLANGCILINT_WANT_VERSION),$(GOLANGCILINT_VERSION)))
check:
	golangci-lint run
else
check:
	docker build -t golangci-lint:fgs . -f Dockerfile.golangci-lint
	docker run --rm -v `pwd`:/app -w /app golangci-lint:fgs golangci-lint run
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
	find . -name '*.go' -not -path './vendor/*' -not -path './api/vendor/*' -not -path './pkg/k8s/vendor/*' -not -path './modules/*' | xargs gofmt -w

.PHONY: format
format: go-format clang-format

.PHONY: headers all clean image install lint hubble-fgs hubble-enterprise generate check


# generate cscope for bpf files
cscope:
	find bpf -name "*.[chxsS]" -print > cscope.files
	cscope -b -q -k
.PHONY: cscope

tester-progs:
	$(MAKE) -C $(TESTER_PROGS_DIR)
.PHONY: tester-progs
