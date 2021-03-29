GO := go
INSTALL = $(QUIET)install
BINDIR ?= /usr/local/bin
CONTAINER_ENGINE ?= docker
DOCKER_IMAGE_TAG ?= latest
LOCAL_CLANG ?= 1
LIBBPF_IMAGE = quay.io/isovalent/hubble-libbpf:v0.2.2
CLANG_IMAGE  = quay.io/isovalent/hubble-llvm:2020-12-29-45f6aa2

LIBBPF_INSTALL_DIR ?= ./lib
CLANG_INSTALL_DIR  ?= ./bin

KATA_RUNNER = docker run --runtime=kata-runtime --cap-add all --ulimit memlock=-1:-1 -v /var/lib/kata-containers/images/btf:/var/lib/hubble-fgs/btf -v $(CURDIR):/go/src/github.com/covalentio/hubble-fgs -v /proc:/procRoot covalentio/hubble-fgs-test


all: hubble-bpf hubble-fgs hubble-enterprise test-compile

.PHONY: hubble-bpf hubble-bpf-local hubble-bpf-container

ifeq (1,$(LOCAL_CLANG))
hubble-bpf: hubble-bpf-local
else
hubble-bpf: hubble-bpf-container
endif

hubble-bpf-local:
	make -C ./bpf

hubble-bpf-container:
	docker rm hubble-llvm || true
	docker run -v $(CURDIR):/hubble-fgs -u $$(id -u)  --name hubble-llvm $(CLANG_IMAGE) make -C /hubble-fgs/bpf
	docker rm hubble-llvm

hubble-fgs:
	$(GO) build -mod=vendor ./cmd/hubble-fgs/

hubble-enterprise:
	$(GO) build -mod=vendor ./cmd/hubble-enterprise/

.PHONY: ksyms
ksyms:
	$(GO) build ./cmd/ksyms/

hubble-fgs-image:
	GOOS=linux GOARCH=amd64 $(GO) build -mod=vendor -ldflags "-linkmode external -extldflags -static" ./cmd/hubble-fgs/
	GOOS=linux GOARCH=amd64 $(GO) build -mod=vendor -ldflags "-linkmode external -extldflags -static" ./cmd/hubble-enterprise/

install:
	groupadd -f hubble
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 ./hubble-fgs $(DESTDIR)$(BINDIR)

clean:
	rm -f $(TARGET)
	make -C ./bpf clean
	rm -f go-tests/*.test


test:
	$(GO) test $(GOFLAGS) -failfast -cover $$(go list $(GOFLAGS) ./...)

test-compile:
	mkdir -p go-tests
	$(GO) test -c ./pkg/bugtool               -o go-tests/bugtool.test
	$(GO) test -c ./pkg/filters               -o go-tests/filters.test
	$(GO) test -c ./pkg/grpc                  -o go-tests/grpc.test
	$(GO) test -c ./pkg/metrics               -o go-tests/metrics.test
	$(GO) test -c ./pkg/observer              -o go-tests/observer.test
	$(GO) test -c ./pkg/reader                -o go-tests/reader.test
	$(GO) test -c ./pkg/stacktracetree        -o go-tests/stacktracetree.test
	$(GO) test -c ./pkg/vtuplefilter          -o go-tests/vtuplefilter.test
	$(GO) test -c ./pkg/tracepoint            -o go-tests/tracepoint.test
	$(GO) test -c ./pkg/config               -o go-tests/config.test

test-kernels:
	#kata-img  vmlinuz-kata-linux-4.14.184-79_hubble
	#${KATA_RUNNER}
	kata-img vmlinuz-kata-linux-4.19.133-81_hubble
	${KATA_RUNNER}
	kata-img vmlinuz-kata-linux-5.4.51-83_hubble
	${KATA_RUNNER}

lint:
	golint -set_exit_status $$(go list ./...)

image:
	$(CONTAINER_ENGINE) build -t "covalentio/hubble-fgs:${DOCKER_IMAGE_TAG}" .
	$(QUIET)echo "Push like this when ready:"
	$(QUIET)echo "${CONTAINER_ENGINE} push covalentio/hubble-fgs:$(DOCKER_IMAGE_TAG)"

image-btf:
	$(CONTAINER_ENGINE) build -f Dockerfile.btf -t "covalentio/hubble-fgs:${DOCKER_IMAGE_TAG}" .
	$(QUIET)echo "Push like this when ready:"
	$(QUIET)echo "${CONTAINER_ENGINE} push covalentio/hubble-fgs:$(DOCKER_IMAGE_TAG)"

image-test:
	$(CONTAINER_ENGINE) build -f Dockerfile.test -t "covalentio/hubble-fgs-test:${DOCKER_IMAGE_TAG}" .
	$(QUIET)echo "Push like this when ready:"
	$(QUIET)echo "${CONTAINER_ENGINE} push covalentio/hubble-fgs-test:$(DOCKER_IMAGE_TAG)"

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

tools-install: libbpf-install clang-install

quick-install:
	helm template ./install/kubernetes/hubble-fgs --namespace kube-system > ./install/kubernetes/quick-install.yaml

generate:
	./tools/controller-gen crd paths=./pkg/k8s/apis/... output:dir=./crds
	bash vendor/k8s.io/code-generator/generate-groups.sh all \
	  github.com/covalentio/hubble-fgs/pkg/k8s/client \
	  github.com/covalentio/hubble-fgs/pkg/k8s/apis \
	  isovalent.com:v1alpha1 \
	  --go-header-file hack/custom-boilerplate.go.txt

.PHONY: headers all clean image install lint hubble-fgs quick-install hubble-enterprise generate
