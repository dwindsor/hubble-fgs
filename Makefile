GO := go
INSTALL = $(QUIET)install
BINDIR ?= /usr/local/bin
CONTAINER_ENGINE ?= docker
DOCKER_IMAGE_TAG ?= latest

all: headers hubble-fgs hubble-fgs-printer

headers:
	cd ./bpf && make copy && make && cd ../

hubble-fgs:
	make -C ./bpf clean && make -C ./bpf copy && make -C ./bpf
	$(GO) build ./cmd/hubble-fgs/

hubble-fgs-image:
	GOOS=linux GOARCH=amd64 $(GO) build -ldflags "-linkmode external -extldflags -static" ./cmd/hubble-fgs/
	GOOS=linux GOARCH=amd64 $(GO) build ./cmd/hubble-fgs-printer/

hubble-fgs-printer:
	$(GO) build ./cmd/hubble-fgs-printer/

install:
	groupadd -f hubble
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 ./hubble-fgs $(DESTDIR)$(BINDIR)

clean:
	rm -f $(TARGET)
	make -C ./bpf clean

lint:
	golint -set_exit_status $$(go list ./...)

image:
	cd ./bpf && ./init.sh && cd ../
	$(CONTAINER_ENGINE) build -t "covalentio/hubble-fgs:${DOCKER_IMAGE_TAG}" .
	$(QUIET)echo "Push like this when ready:"
	$(QUIET)echo "${CONTAINER_ENGINE} push covalentio/hubble-fgs:$(DOCKER_IMAGE_TAG)"

.PHONY: headers all clean image install lint hubble-fgs
