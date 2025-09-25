GOARCH ?= $(shell go env GOARCH)
GOOS ?= linux
ARCH ?= $(GOARCH)
OS ?= $(GOOS)
DIST = $(shell pwd)/dist

# Version information
VERSION ?= v0.1.1
GIT_SHA ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
FULL_VERSION = $(VERSION)-$(GIT_SHA)

# Docker build variables
DOCKER_BUILD_IMAGE_TAG ?= $(FULL_VERSION)
DOCKER_BUILD_IMAGE_REPO ?= hypershield
DOCKER_BUILD_IMAGE_CACHE_REPO ?= hypershield
DOCKER_BUILD_PLATFORM ?= $(OS)/$(ARCH)

all: docker-dist-elba

define package
	@cd $(1) ; make package
	-mv $(1)/*.deb $(DIST)
	-mv $(1)/*.tar.gz $(DIST)
	-mv $(1)/*.sha256 $(DIST)
endef

PHONY += dist
dist:
	mkdir -p $(DIST)
	$(call package, agent)

PHONY += clean
clean:
	rm -rf $(DIST)
	cd agent ; make clean

PHONY += clean-all
clean-all:	clean
	cd agent ; make clean-all

PHONY += docker-dist-*
docker-dist-%: docker-build-%
	$(eval CONTAINER_ID := $(shell docker create $(DOCKER_BUILD_IMAGE_REPO)/$*-fwa:$(DOCKER_BUILD_IMAGE_TAG)))
	docker cp $(CONTAINER_ID):/src/dist $(DIST)
	docker rm $(CONTAINER_ID)

PHONY += docker-build-*
docker-build-%:
	DOCKER_BUILDKIT=1 docker build -t $(DOCKER_BUILD_IMAGE_REPO)/$*-fwa:$(DOCKER_BUILD_IMAGE_TAG) \
		-f build/Dockerfile \
		--build-arg="TARGET=$*" \
		--build-arg="BUILD_PLATFORM=$(DOCKER_BUILD_PLATFORM)" \
		--cache-from $(DOCKER_BUILD_IMAGE_CACHE_REPO)/$*-fwa:$(DOCKER_BUILD_IMAGE_TAG) \
		--target $* ../../.

.PHONY = $(PHONY)
