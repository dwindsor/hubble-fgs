ROOT = $(shell pwd)
ARCH ?= $(shell uname -m)
PLATFORM ?= generic
BUILD_TYPE ?= debug

DEP_SRC = $(ROOT)/src
DEP_STAGE = $(ROOT)/stage
DEP_PATCHES = $(ROOT)/patches
PREFIX = $(ROOT)/stage/usr

CURL_FLAGS = -fsSL --retry 5 --retry-max-time 120
CC = gcc

# Direct dependencies
GO_VERSION = 1.24.4

all: packages go

# Deps for packages
DISTRO = $(shell . /etc/os-release && echo $$ID || echo "unknown")
ifeq ($(DISTRO),ubuntu)
	PKG_MANAGER = apt-get
else ifeq ($(DISTRO),debian)
	PKG_MANAGER = apt-get
else ifeq ($(DISTRO),centos)
	PKG_MANAGER = yum
else ifeq ($(DISTRO),rhel)
	PKG_MANAGER = yum
else ifeq ($(DISTRO),fedora)
	PKG_MANAGER = yum
endif

PHONY := packages
packages:
ifeq ($(PKG_MANAGER),apt-get)
	apt-get update
	apt-get install -y \
		build-essential \
		ca-certificates \
		cmake \
		curl \
		git
else ifeq ($(PKG_MANAGER),yum)
	yum update
	yum install -y \
		gcc \
		ca-certificates \
		cmake \
		curl \
		git
endif

# Deps for go
ARCH = $(shell uname -m | sed -e 's/aarch64/arm64/' -e 's/x86_64/amd64/' -e 's/.*/linux-&/')

PHONY += go
go:
	mkdir -p $(DEP_SRC); mkdir -p $(DEP_STAGE)/go-$(GO_VERSION)
	curl $(CURL_FLAGS) https://go.dev/dl/go$(GO_VERSION).$(ARCH).tar.gz | tar -xvzf - -C $(DEP_SRC)
	mv $(DEP_SRC)/go /usr/local/go-$(GO_VERSION)
	ln -s -f /usr/local/go-$(GO_VERSION)/bin/go /usr/bin/go
	ln -s -f /usr/local/go-$(GO_VERSION) /usr/local/go
	GOBIN=/usr/local/bin go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28
	GOBIN=/usr/local/bin go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2

PHONY += clean
clean:
	rm -rf $(DEP_SRC) $(DEP_STAGE)

.PHONY = $(PHONY)
