GO := go
INSTALL = $(QUIET)install
BINDIR ?= /usr/local/bin
CONTAINER_ENGINE ?= docker
DOCKER_IMAGE_TAG ?= latest
LOCAL_CLANG ?= 1
LOCAL_CLANG_FORMAT ?= 0
FORMAT_FIND_FLAGS ?= -name '*.c' -o -name '*.h' -not -path 'bpf/include/vmlinux.h' -not -path 'bpf/include/api.h' -not -path 'bpf/libbpf/*'
NOOPT ?= 0
LIBBPF_IMAGE = quay.io/isovalent/hubble-libbpf:v0.2.3
CLANG_IMAGE  = quay.io/isovalent/hubble-llvm:2020-12-29-45f6aa2
METADATA_IMAGE = quay.io/isovalent/hubble-enterprise-metadata

LIBBPF_INSTALL_DIR ?= ./lib
CLANG_INSTALL_DIR  ?= ./bin
VERSION=$(shell git describe --tags --always)
GO_GCFLAGS ?= ""
GO_LDFLAGS="-X 'github.com/isovalent/hubble-fgs/pkg/version.Version=$(VERSION)'"
GO_IMAGE_LDFLAGS="-X 'github.com/isovalent/hubble-fgs/pkg/version.Version=$(VERSION)' -linkmode external -extldflags -static"
GO_OPERATOR_IMAGE_LDFLAGS="-X 'github.com/isovalent/hubble-fgs/pkg/version.Version=$(VERSION)' -s -w"

KATA_RUNNER = docker run --runtime=kata-runtime --cap-add all --ulimit memlock=-1:-1 -v /var/lib/kata-containers/images/btf:/var/lib/hubble-fgs/btf -v $(CURDIR):/go/src/github.com/isovalent/hubble-fgs -v /proc:/procRoot isovalent/hubble-fgs-test

GOLANGCILINT_WANT_VERSION = 1.45.2
GOLANGCILINT_VERSION = $(shell golangci-lint version 2>/dev/null)

# Directories to enforce copyright headers on
COPYRIGHT_DIRS = pkg/bench cmd/fgs-bench bpf/parsers/http

all: hubble-bpf hubble-fgs hubble-enterprise fgs-bench fgs-alignchecker test-compile contrib-progs checkerpc

.PHONY: hubble-bpf hubble-bpf-local hubble-bpf-container

-include Makefile.docker

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
	docker rm hubble-llvm || true
	docker run -v $(CURDIR):/hubble-fgs -u $$(id -u)  --name hubble-llvm $(CLANG_IMAGE) $(MAKE) -C /hubble-fgs/bpf
	docker rm hubble-llvm

hubble-fgs:
	$(GO) build -tags enterprise -gcflags=$(GO_GCFLAGS) -ldflags=$(GO_LDFLAGS) -mod=vendor ./cmd/hubble-fgs/

hubble-enterprise:
	$(GO) build -gcflags=$(GO_GCFLAGS) -ldflags=$(GO_LDFLAGS) -mod=vendor ./cmd/hubble-enterprise/

hubble-enterprise-operator:
	$(GO) build -gcflags=$(GO_GCFLAGS) -ldflags=$(GO_LDFLAGS) -mod=vendor -o $@ ./operator

fgs-alignchecker:
	$(GO) build -gcflags=$(GO_GCFLAGS) -ldflags=$(GO_LDFLAGS) -mod=vendor -o $@ ./tools/alignchecker/

checkerpc:
	$(GO) build -gcflags=$(GO_GCFLAGS) -ldflags=$(GO_LDFLAGS) -mod=vendor -o $@ ./cmd/checkerpc/

.PHONY: ksyms
ksyms:
	$(GO) build ./cmd/ksyms/

hubble-fgs-image:
	GOOS=linux GOARCH=amd64 $(GO) build -tags enterprise,netgo -mod=vendor -ldflags=$(GO_IMAGE_LDFLAGS) ./cmd/hubble-fgs/
	GOOS=linux GOARCH=amd64 $(GO) build -tags enterprise,netgo -mod=vendor -ldflags=$(GO_IMAGE_LDFLAGS) ./cmd/hubble-enterprise/

hubble-enterprise-operator-image:
	CGO_ENABLED=0 $(GO) build -ldflags=$(GO_OPERATOR_IMAGE_LDFLAGS) -mod=vendor -o hubble-enterprise-operator ./operator

install:
	groupadd -f hubble
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 ./hubble-fgs $(DESTDIR)$(BINDIR)

clean:
	$(MAKE) -C ./bpf clean
	rm -f go-tests/*.test ./ksyms ./hubble-enterprise ./hubble-enterprise-operator ./hubble-fgs ./fgs-alignchecker ./fgs-bench ./checkerpc
	rm -f contrib/sigkill-tester/sigkill-tester contrib/namespace-tester/test_ns contrib/capabilities-tester/test_caps

.PHONY: fgs-bench fgs-bench-image
fgs-bench:
	$(GO) build -tags enterprise ./cmd/fgs-bench

fgs-bench-image:
	GOOS=linux GOARCH=amd64 $(GO) build -mod=vendor -ldflags=$(GO_IMAGE_LDFLAGS) ./cmd/fgs-bench

parsertest-image:
	GOOS=linux GOARCH=amd64 $(GO) test -mod=vendor -ldflags=$(GO_IMAGE_LDFLAGS) -c ./pkg/parsertest -o parsertest

package-fgs-bench: hubble-bpf-local fgs-bench
	tar --transform="s|^|fgs-bench/|" \
	    -czhf fgs-bench.tar.gz bpf/objs/*.o fgs-bench lib/libbpf.so.0

test:
	ulimit -n 1048576 && $(GO) test -p 1 -parallel 1 $(GOFLAGS) -gcflags=$(GO_GCFLAGS) -timeout 20m -failfast -cover ./...

test-compile:
	mkdir -p go-tests
	$(GO) test -gcflags=$(GO_GCFLAGS) -c ./pkg/bugtool         -o go-tests/bugtool.test
	$(GO) test -gcflags=$(GO_GCFLAGS) -c ./pkg/filters         -o go-tests/filters.test
	$(GO) test -gcflags=$(GO_GCFLAGS) -c ./pkg/grpc            -o go-tests/grpc.test
	$(GO) test -gcflags=$(GO_GCFLAGS) -c ./pkg/metrics         -o go-tests/metrics.test
	$(GO) test -gcflags=$(GO_GCFLAGS) -c ./pkg/observer        -o go-tests/observer.test
	$(GO) test -gcflags=$(GO_GCFLAGS) -c ./pkg/reader          -o go-tests/reader.test
	$(GO) test -gcflags=$(GO_GCFLAGS) -c ./pkg/stacktracetree  -o go-tests/stacktracetree.test
	$(GO) test -gcflags=$(GO_GCFLAGS) -c ./pkg/vtuplefilter    -o go-tests/vtuplefilter.test
	$(GO) test -gcflags=$(GO_GCFLAGS) -c ./pkg/tracepoint      -o go-tests/tracepoint.test
	$(GO) test -gcflags=$(GO_GCFLAGS) -c ./pkg/config          -o go-tests/config.test
	$(GO) test -gcflags=$(GO_GCFLAGS) -c ./pkg/idtable         -o go-tests/idtable.test
	$(GO) test -gcflags=$(GO_GCFLAGS) -c ./pkg/sensors/sockmap -o go-tests/sockmap.test
	$(GO) test -gcflags=$(GO_GCFLAGS) -c ./pkg/parsertest      -o go-tests/parsertest.test
	$(GO) test -gcflags=$(GO_GCFLAGS) -c ./pkg/bpf             -o go-tests/bpf.test
	$(GO) test -gcflags=$(GO_GCFLAGS) -c ./pkg/btf             -o go-tests/btf.test
	$(GO) test -gcflags=$(GO_GCFLAGS) -c ./pkg/sensors/udp     -o go-tests/udp.test

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

image-btf:
	$(CONTAINER_ENGINE) build -f Dockerfile.btf -t "isovalent/hubble-fgs:${DOCKER_IMAGE_TAG}" .
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

.PHONY: tools-install tools-clean libbpf-install clang-install
tools-install: libbpf-install clang-install
tools-clean:
	rm -rf $(LIBBPF_INSTALL_DIR)
	rm -rf $(CLANG_INSTALL_DIR)
libbpf-install:
	$(eval id=$(shell docker create $(LIBBPF_IMAGE)))
	mkdir -p $(LIBBPF_INSTALL_DIR)
	docker cp ${id}:/go/src/github.com/covalentio/hubble-fgs/src/libbpf.so $(LIBBPF_INSTALL_DIR)
	docker cp ${id}:/go/src/github.com/covalentio/hubble-fgs/src/libbpf.so.0 $(LIBBPF_INSTALL_DIR)
	docker cp ${id}:/go/src/github.com/covalentio/hubble-fgs/src/libbpf.so.0.2.0 $(LIBBPF_INSTALL_DIR)
	docker stop ${id}

clang-install:
	$(eval id=$(shell docker create $(CLANG_IMAGE)))
	mkdir -p $(CLANG_INSTALL_DIR)
	docker cp ${id}:/usr/local/bin/clang-11 $(CLANG_INSTALL_DIR)/clang
	docker cp ${id}:/usr/local/bin/llc $(CLANG_INSTALL_DIR)/llc
	docker stop ${id}

fetch-testdata:
	docker stop fgs-md-temp || true
	docker rm fgs-md-temp || true
	docker create --name fgs-md-temp $(METADATA_IMAGE)
	mkdir -p testdata/btf
	docker cp fgs-md-temp:/var/run/hubble-fgs/vmlinux-5.4.104+ testdata/btf
	docker stop fgs-md-temp || true

generate:
	./tools/controller-gen crd paths=./pkg/k8s/apis/... output:dir=pkg/k8s/apis/isovalent.com/client/crds/v1alpha1
	export GOPATH=$$(go env GOPATH); \
	  bash vendor/k8s.io/code-generator/generate-groups.sh all \
	  github.com/isovalent/hubble-fgs/pkg/k8s/client \
	  github.com/isovalent/hubble-fgs/pkg/k8s/apis \
	  isovalent.com:v1alpha1 \
	  --go-header-file hack/custom-boilerplate.go.txt

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
	find . -name '*.go' -not -path './vendor/*' | xargs gofmt -w

.PHONY: format
format: go-format clang-format

.PHONY: headers all clean image install lint hubble-fgs hubble-enterprise generate check checkerpc


# generate cscope for bpf files
cscope:
	find bpf -name "*.[chxsS]" -print > cscope.files
	cscope -b -q -k
.PHONY: cscope

contrib-progs:
	$(MAKE) -C contrib/sigkill-tester
	$(MAKE) -C contrib/namespace-tester
	$(MAKE) -C contrib/capabilities-tester
.PHONY: contrib-progs
