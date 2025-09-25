export PROJECT_ROOT=$(shell pwd)
export GO111MODULE=on
export GOPRIVATE="github.com/isovalent"
#export GOPROXY="https://proxy.golang.org, https://${ARTIFACTORY_USER}:${ARTIFACTORY_PASSWORD}@engci-maven-master.cisco.com/artifactory/api/go/nyota-go, direct"
REPO_NAME = github.com/isovalent/hubble-fgs
export ARCH ?= $(shell uname -m)
ifeq ($(ARCH), aarch64)
GOARCH=arm64
else ifeq ($(ARCH), x86_64)
GOARCH=amd64
endif
#for packaging
export PLATFORM ?= generic
PKGDIR = ./packaging
DIST = $(shell pwd)/dist

.PHONY: clean
clean:
	@echo "Cleaning up"
	rm -rf packaging/build *.gz *.deb *.sha256
	rm -rf coverage coverage.html
	rm -f hs-cp-fwa hs-cp-fwa.dpu hs-cp-fwactl

.PHONY: clean-all
clean-all: clean
	@echo "Cleaning up all"
	rm -rf $(DIST)

.PHONY: package
package:
	@echo "Packaging"
	mkdir -p $(DIST)
	cd packaging; cmake -B build -DPACKAGE_PLATFORM=$(PLATFORM) .
	make -C packaging/build package
	-cp $(PKGDIR)/build/build/*.deb $(DIST)
	-cp $(PKGDIR)/build/build/*.tar.gz $(DIST)
	-cp $(PKGDIR)/build/build/*.sha256 $(DIST)
	-mv $(PKGDIR)/build/build/*.gz .
	-mv $(PKGDIR)/build/build/*.deb .
	-mv $(PKGDIR)/build/build/*.sha256 .
