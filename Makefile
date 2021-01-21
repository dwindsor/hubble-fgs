GO := go
INSTALL = $(QUIET)install
BINDIR ?= /usr/local/bin
CONTAINER_ENGINE ?= docker
DOCKER_IMAGE_TAG ?= latest
LOCAL_CLANG ?= 1
LIBBPF_IMAGE = quay.io/isovalent/hubble-libbpf:v0.2.2
CLANG_IMAGE = quay.io/isovalent/hubble-llvm:2020-12-29-45f6aa2

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

test:
	$(GO) test $(GOFLAGS) -cover $$(go list $(GOFLAGS) ./...)

test-compile:
	$(GO) test -c ./pkg/bugtool
	$(GO) test -c ./pkg/filters
	$(GO) test -c ./pkg/grpc
	$(GO) test -c ./pkg/metrics
	$(GO) test -c ./pkg/observer
	$(GO) test -c ./pkg/reader
	$(GO) test -c ./pkg/stacktracetree
	$(GO) test -c ./pkg/vtuplefilter

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

libbpf:
	$(eval id=$(shell docker create $(LIBBPF_IMAGE)))
	mkdir -p lib
	docker cp ${id}:/go/src/github.com/covalentio/hubble-fgs/src/libbpf.so ./lib/
	docker cp ${id}:/go/src/github.com/covalentio/hubble-fgs/src/libbpf.so.0 ./lib/
	docker cp ${id}:/go/src/github.com/covalentio/hubble-fgs/src/libbpf.so.0.2.0 ./lib/
	docker stop ${id}

quick-install:
	helm template ./install/kubernetes/hubble-fgs --namespace kube-system > ./install/kubernetes/quick-install.yaml

.PHONY: headers all clean image install lint hubble-fgs quick-install hubble-enterprise
