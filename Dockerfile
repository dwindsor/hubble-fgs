# This Dockerfile can be used to compile natively on amd64 and cross-compile on
# amd64 for arm64.
#
# It can technically build natively on arm64 and cross-compile on arm64 for
# amd64 but the steps involving the gcc cross compiler might need rework. It's
# assumed that if [ $BUILDARCH != $TARGETARCH ] we are cross-compiling from
# amd64 to arm64
#
# For help on Docker cross compilation see the following blogpost:
# https://www.docker.com/blog/faster-multi-platform-builds-dockerfile-cross-compilation-guide/

# renovate: datasource=docker depName=artifactory.devhub-cloud.cisco.com/sto-cg-docker/chainguard-base
ARG APK_IMAGE=artifactory.devhub-cloud.cisco.com/sto-cg-docker/chainguard-base:v20230214-2026.09.28
# renovate: datasource=docker depName=artifactory.devhub-cloud.cisco.com/sto-cg-docker/static
ARG BASE_IMAGE=artifactory.devhub-cloud.cisco.com/sto-cg-docker/static:latest-2026.09.24

# First builder (cross-)compile the BPF programs
FROM --platform=$BUILDPLATFORM quay.io/cilium/clang:969f95f8ef7923af36bf657ba6d4c65691f56882@sha256:ff83e52d3ea150b3d93e4ae40ae86620003ac3f6d91fe6e939dcc95469f83ff2 AS bpf-builder
WORKDIR /go/src/github.com/isovalent/hubble-fgs
RUN apt-get update && apt-get install -y linux-libc-dev ccache
COPY . ./
ARG TARGETARCH
ARG DEBUG
ARG LSEG
RUN --mount=type=cache,target=/root/.cache/ccache \ 
    make tetragon-bpf LOCAL_CLANG=1 TARGET_ARCH=$TARGETARCH DEBUG=$DEBUG LSEG=$LSEG CLANG="ccache clang"

# Second builder (cross-)compile:
# - tetragon-fs-scanner (this one compiles a C program, so a gcc cross compiler is needed)
# - tetragon
# - tetra
# Using Debian golang image for cross-compilation support (needs apt-get for crossbuild-essential)
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.27.1@sha256:f44f6e88636cfb311f9ebace870ded69d943f227bb3cb27d32ffd84ea18c43ea AS tetragon-builder
WORKDIR /go/src/github.com/isovalent/hubble-fgs
ARG TARGETARCH BUILDARCH
ARG LSEG
RUN apt-get update
RUN if [ $BUILDARCH != $TARGETARCH ]; \
    then apt-get install -y libelf-dev zlib1g-dev crossbuild-essential-$TARGETARCH; \
    else apt-get install -y libelf-dev zlib1g-dev; fi
RUN ldconfig /usr/local/
COPY . ./
RUN --mount=type=cache,target=/go/pkg/mod \ 
    --mount=type=cache,target=/root/.cache/go-build \
    if [ $BUILDARCH != $TARGETARCH ]; \
    then make tetragon tetra tetragon-fs-scanner TARGET_ARCH=$TARGETARCH CC=aarch64-linux-gnu-gcc LSEG=$LSEG; \
    else make tetragon tetra tetragon-fs-scanner TARGET_ARCH=$TARGETARCH LSEG=$LSEG; fi

# Third builder (cross-)compile a stripped gops
# Chainguard go-dev image
# renovate: datasource=docker depName=artifactory.devhub-cloud.cisco.com/sto-cg-docker/go
FROM --platform=$BUILDPLATFORM artifactory.devhub-cloud.cisco.com/sto-cg-docker/go:v1.27.1-dev@sha256:6d22a8f256cda4b0c2a20447709e1ebe805546a7a3ea50fb889ec92e49c5fdb5 AS gops
ARG TARGETARCH
# Chainguard go-dev uses wolfi, install binutils and git via apk
RUN apk add --no-cache binutils git \
 && git clone https://github.com/google/gops /go/src/github.com/google/gops \
 && cd /go/src/github.com/google/gops \
 && git checkout -b v0.3.27 v0.3.27 \
 && GOARCH=$TARGETARCH go build -ldflags="-s -w" .

# This builder (cross-)compile a stripped static version of bpftool.
# This step was kept because the downloaded version includes LLVM libs with the
# disassembler that makes the static binary grow from ~2Mo to ~30Mo.
FROM --platform=$BUILDPLATFORM quay.io/cilium/clang:969f95f8ef7923af36bf657ba6d4c65691f56882@sha256:ff83e52d3ea150b3d93e4ae40ae86620003ac3f6d91fe6e939dcc95469f83ff2 AS bpftool-builder
WORKDIR /bpftool
ARG TARGETARCH BUILDARCH
RUN if [ $BUILDARCH != $TARGETARCH ]; \
    then apt-get update && echo "Types: deb\n\
URIs: http://archive.ubuntu.com/ubuntu/\n\
Suites: noble noble-updates noble-backports\n\
Components: main universe restricted multiverse\n\
Architectures: amd64\n\
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n\
\n\
Types: deb\n\
URIs: http://archive.ubuntu.com/ubuntu/\n\
Suites: noble-security\n\
Components: main universe restricted multiverse\n\
Architectures: amd64\n\
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n\
\n\
Types: deb\n\
URIs: http://ports.ubuntu.com/\n\
Suites: noble noble-updates noble-backports noble-security\n\
Components: main universe restricted multiverse\n\
Architectures: arm64\n\
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg" > /etc/apt/sources.list.d/ubuntu.sources \
    && dpkg --add-architecture arm64; fi
RUN apt-get update
RUN if [ $BUILDARCH != $TARGETARCH ]; \
    then apt-get install -y curl git llvm gcc pkg-config zlib1g-dev libelf-dev libssl-dev libelf-dev:arm64 libcap-dev:arm64 libssl-dev:arm64 crossbuild-essential-$TARGETARCH; \
    else apt-get install -y curl git llvm gcc pkg-config zlib1g-dev libelf-dev libcap-dev libssl-dev; fi
# renovate: datasource=github-releases depName=libbpf/bpftool
ARG BPFTOOL_TAG=v7.7.0
RUN git clone https://github.com/libbpf/bpftool.git . && git checkout ${BPFTOOL_TAG} && git submodule update --init --recursive
RUN if [ $BUILDARCH != $TARGETARCH ]; \
    then make -C src EXTRA_CFLAGS=--static CC=aarch64-linux-gnu-gcc -j $(nproc) && aarch64-linux-gnu-strip src/bpftool; \
    else make -C src EXTRA_CFLAGS=--static -j $(nproc) && strip src/bpftool; fi

# This stage downloads a stripped static version of bpftool with LLVM disassembler
FROM --platform=$BUILDPLATFORM quay.io/cilium/alpine-curl@sha256:408430f548a8390089b9b83020148b0ef80b0be1beb41a98a8bfe036709c196e AS bpftool-downloader
ARG TARGETARCH
# renovate: datasource=github-releases depName=libbpf/bpftool
ARG BPFTOOL_TAG=v7.7.0
RUN curl -L https://github.com/libbpf/bpftool/releases/download/${BPFTOOL_TAG}/bpftool-${BPFTOOL_TAG}-${TARGETARCH}.tar.gz | tar xz && chmod +x bpftool

# Install runtime APK dependencies into a clean rootfs so APK repository
# credentials from the builder image are not copied into final images.
FROM ${BASE_IMAGE} AS static-base
FROM ${APK_IMAGE} AS runtime-deps
COPY --from=static-base / /rootfs
RUN apk add --no-cache --no-commit-hooks --root /rootfs \
    bash \
    busybox \
    ca-certificates \
    glibc \
    iproute2 \
    ld-linux \
    libgcc \
    libstdc++ \
    openssl \
    && rm -rf /rootfs/etc/apk /rootfs/etc/apko.json \
    && rm -rf /rootfs/var/cache/apk/*

# Almost final step runs on target platform (might need emulation) and
# retrieves (cross-)compiled binaries from builders
FROM scratch AS base-build
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/bin:/usr/sbin:/sbin:/bin
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
USER root
COPY --from=runtime-deps /rootfs/ /
RUN addgroup -S hubble	       && \
    mkdir /var/lib/tetragon/ && \
    mkdir /var/run/tetragon/ && \
    mkdir libs		       && \
    mkdir -p /etc/tetragon/tetragon.conf.d/ && \
    mkdir -p /etc/tetragon/tetragon.tp.d/ && \
    mkdir -p /etc/tetragon/tetragon.policies.d/
COPY --from=tetragon-builder /go/src/github.com/isovalent/hubble-fgs/tetragon /usr/bin/
COPY --from=tetragon-builder /go/src/github.com/isovalent/hubble-fgs/tetra /usr/bin/
COPY --from=gops /go/src/github.com/google/gops/gops /usr/bin/
COPY --from=bpf-builder /go/src/github.com/isovalent/hubble-fgs/bpf/objs/* /var/lib/tetragon/
COPY --from=tetragon-builder /go/src/github.com/isovalent/hubble-fgs/bpf/objs/tetragon-fs-scanner /var/lib/tetragon/
COPY --from=tetragon-builder /go/src/github.com/isovalent/hubble-fgs/bpf/objs/tetragon-runner /var/lib/tetragon/
ENTRYPOINT ["/usr/bin/tetragon"]

# This target only builds with the `--target release` option and reduces the
# size of the final image with a static build of bpftool without the LLVM
# disassembler
FROM base-build AS release
COPY --from=bpftool-builder bpftool/src/bpftool /usr/bin/bpftool

FROM base-build
COPY --from=bpftool-downloader /bpftool /usr/bin/bpftool
