GO := go
INSTALL = $(QUIET)install
BINDIR ?= /usr/local/bin
CONTAINER_ENGINE ?= docker
DOCKER_IMAGE_TAG ?= latest

KATA_RUNNER = docker run --runtime=kata-runtime --cap-add all --ulimit memlock=-1:-1 -v /var/lib/kata-containers/images/btf:/var/lib/hubble-fgs/btf -v /home/john/go/src/github.com/covalentio/hubble-fgs:/go/src/github.com/covalentio/hubble-fgs -v /proc:/procRoot covalentio/hubble-fgs-test

all: headers hubble-bpf hubble-fgs hubble-enterprise

headers:
	cd ./bpf && make && cd ../

hubble-bpf:
	make -C ./bpf

hubble-fgs:
	$(GO) build ./cmd/hubble-fgs/

hubble-enterprise:
	$(GO) build ./cmd/hubble-enterprise/

hubble-fgs-image:
	GOOS=linux GOARCH=amd64 $(GO) build ./cmd/hubble-fgs/
	GOOS=linux GOARCH=amd64 $(GO) build ./cmd/hubble-enterprise/

install:
	groupadd -f hubble
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 ./hubble-fgs $(DESTDIR)$(BINDIR)

clean:
	rm -f $(TARGET)
	make -C ./bpf clean

test:
	$(GO) test $(GOFLAGS) -cover $$(go list $(GOFLAGS) ./...)

test-kernels:
	kata-img  vmlinuz-kata-linux-4.14.184-79_hubble
	${KATA_RUNNER}
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

quick-install:
	helm template ./install/kubernetes/hubble-fgs --namespace kube-system > ./install/kubernetes/quick-install.yaml

.PHONY: headers all clean image install lint hubble-fgs quick-install hubble-enterprise
