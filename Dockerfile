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

# First builder (cross-)compile the BPF programs
FROM --platform=$BUILDPLATFORM quay.io/cilium/clang:b97f5b3d5c38da62fb009f21a53cd42aefd54a2f@sha256:e1c8ed0acd2e24ed05377f2861d8174af28e09bef3bbc79649c8eba165207df0 AS bpf-builder
WORKDIR /go/src/github.com/isovalent/hubble-fgs
RUN apt-get update && apt-get install -y linux-libc-dev ccache
COPY . ./
ARG TARGETARCH
ARG DEBUG
RUN --mount=type=cache,target=/root/.cache/ccache \ 
    make tetragon-bpf LOCAL_CLANG=1 TARGET_ARCH=$TARGETARCH DEBUG=$DEBUG CLANG="ccache clang"

# Second builder (cross-)compile:
# - tetragon-fs-scanner (this one compiles a C program, so a gcc cross compiler is needed)
# - tetragon
# - tetra
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.26.2@sha256:2a2b4b5791cea8ae09caecba7bad0bd9631def96e5fe362e4a5e67009fe4ae61 AS tetragon-builder
WORKDIR /go/src/github.com/isovalent/hubble-fgs
ARG TARGETARCH BUILDARCH
RUN apt-get update
RUN if [ $BUILDARCH != $TARGETARCH ]; \
    then apt-get install -y libelf-dev zlib1g-dev crossbuild-essential-$TARGETARCH; \
    else apt-get install -y libelf-dev zlib1g-dev; fi
RUN ldconfig /usr/local/
COPY . ./
RUN --mount=type=cache,target=/go/pkg/mod \ 
    --mount=type=cache,target=/root/.cache/go-build \
    if [ $BUILDARCH != $TARGETARCH ]; \
    then make tetragon tetra tetragon-fs-scanner TARGET_ARCH=$TARGETARCH CC=aarch64-linux-gnu-gcc; \
    else make tetragon tetra tetragon-fs-scanner TARGET_ARCH=$TARGETARCH; fi

# Third builder (cross-)compile a stripped gops
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.26.2-alpine@sha256:c2a1f7b2095d046ae14b286b18413a05bb82c9bca9b25fe7ff5efef0f0826166 AS gops
ARG TARGETARCH
RUN apk add --no-cache binutils git \
 && git clone https://github.com/google/gops /go/src/github.com/google/gops \
 && cd /go/src/github.com/google/gops \
 && git checkout -b v0.3.27 v0.3.27 \
 && GOARCH=$TARGETARCH go build -ldflags="-s -w" .

# This builder (cross-)compile a stripped static version of bpftool.
# This step was kept because the downloaded version includes LLVM libs with the
# disassembler that makes the static binary grow from ~2Mo to ~30Mo.
FROM --platform=$BUILDPLATFORM quay.io/cilium/clang:b97f5b3d5c38da62fb009f21a53cd42aefd54a2f@sha256:e1c8ed0acd2e24ed05377f2861d8174af28e09bef3bbc79649c8eba165207df0 AS bpftool-builder
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
    then apt-get install -y curl git llvm gcc pkg-config zlib1g-dev libelf-dev libelf-dev:arm64 libcap-dev:arm64 crossbuild-essential-$TARGETARCH; \
    else apt-get install -y curl git llvm gcc pkg-config zlib1g-dev libelf-dev libcap-dev; fi
# v7.1.0
ENV BPFTOOL_REV="b01941c8f7890489f09713348a7d89567538504b"
RUN git clone https://github.com/libbpf/bpftool.git . && git checkout ${BPFTOOL_REV} && git submodule update --init --recursive
# From Ubuntu 24.04 builder image, libzstd must be added at the end of LIBS and LIBS_BOOTSTRAP to compile statically
RUN sed -i 's/\(LIBS = $(LIBBPF) -lelf -lz\)/\1 -lzstd/; s/\(LIBS_BOOTSTRAP = $(LIBBPF_BOOTSTRAP) -lelf -lz\)/\1 -lzstd/' src/Makefile
RUN if [ $BUILDARCH != $TARGETARCH ]; \
    then make -C src EXTRA_CFLAGS=--static CC=aarch64-linux-gnu-gcc -j $(nproc) && aarch64-linux-gnu-strip src/bpftool; \
    else make -C src EXTRA_CFLAGS=--static -j $(nproc) && strip src/bpftool; fi

# This stage downloads a stripped static version of bpftool with LLVM disassembler
FROM --platform=$BUILDPLATFORM quay.io/cilium/alpine-curl@sha256:408430f548a8390089b9b83020148b0ef80b0be1beb41a98a8bfe036709c196e AS bpftool-downloader
ARG TARGETARCH
ARG BPFTOOL_TAG=v7.2.0-snapshot.0
RUN curl -L https://github.com/libbpf/bpftool/releases/download/${BPFTOOL_TAG}/bpftool-${BPFTOOL_TAG}-${TARGETARCH}.tar.gz | tar xz && chmod +x bpftool

# Almost final step runs on target platform (might need emulation) and
# retrieves (cross-)compiled binaries from builders
FROM docker.io/library/alpine:3.23.4@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11 AS base-build
RUN apk add --no-cache iproute2
RUN addgroup hubble	       && \
    mkdir /var/lib/tetragon/ && \
    mkdir /var/run/tetragon/ && \
    mkdir libs		       && \
    mkdir -p /etc/tetragon/tetragon.conf.d/ && \
    mkdir -p /etc/tetragon/tetragon.tp.d/ && \
    mkdir -p /etc/tetragon/tetragon.policies.d/ && \
    apk add --no-cache --update bash
RUN apk upgrade --no-cache
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
