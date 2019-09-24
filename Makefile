GO := go
INSTALL = $(QUIET)install
BINDIR ?= /usr/local/bin
CONTAINER_ENGINE ?= docker
DOCKER_IMAGE_TAG ?= latest

all: hubble-fgs hubble-fgs-printer

hubble-fgs:
	$(GO) build ./cmd/hubble-fgs/

hubble-fgs-printer:
	$(GO) build ./cmd/hubble-fgs-printer/

install:
	groupadd -f hubble
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 ./hubble-fgs $(DESTDIR)$(BINDIR)

clean:
	rm -f $(TARGET)

lint:
	golint -set_exit_status $$(go list ./...)

image:
	cd ./bpf && ./init.sh && cd ../
	$(CONTAINER_ENGINE) build -t "covalentio/hubble-fgs:${DOCKER_IMAGE_TAG}" .
	$(QUIET)echo "Push like this when ready:"
	$(QUIET)echo "${CONTAINER_ENGINE} push covalentio/hubble-fgs:$(DOCKER_IMAGE_TAG)"

.PHONY: all clean image install lint hubble-fgs
