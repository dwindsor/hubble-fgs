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
FROM --platform=$BUILDPLATFORM quay.io/cilium/clang@sha256:b440ae7b3591a80ffef8120b2ac99e802bbd31dee10f5f15a48566832ae0866f AS bpf-builder
WORKDIR /go/src/github.com/isovalent/hubble-fgs
RUN apt-get update && apt-get install -y linux-libc-dev
COPY . ./
ARG TARGETARCH
RUN make tetragon-bpf LOCAL_CLANG=1 TARGET_ARCH=$TARGETARCH

# Second builder (cross-)compile:
# - tetragon-fs-scanner (this one compiles a C program, so a gcc cross compiler is needed)
# - tetragon
# - tetra
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.23.5@sha256:8c10f21bec412f08f73aa7b97ca5ac5f28a39d8a88030ad8a339fd0a781d72b4 AS tetragon-builder
WORKDIR /go/src/github.com/isovalent/hubble-fgs
ARG TARGETARCH BUILDARCH
RUN apt-get update
RUN if [ $BUILDARCH != $TARGETARCH ]; \
    then apt-get install -y libelf-dev zlib1g-dev crossbuild-essential-$TARGETARCH; \
    else apt-get install -y libelf-dev zlib1g-dev; fi
RUN ldconfig /usr/local/
COPY . ./
RUN if [ $BUILDARCH != $TARGETARCH ]; \
    then make tetragon tetra tetragon-fs-scanner tetragon-oci-hook tetragon-oci-hook-setup TARGET_ARCH=$TARGETARCH CC=aarch64-linux-gnu-gcc; \
    else make tetragon tetra tetragon-fs-scanner tetragon-oci-hook tetragon-oci-hook-setup TARGET_ARCH=$TARGETARCH; fi

# Third builder (cross-)compile a stripped gops
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.23.5-alpine@sha256:47d337594bd9e667d35514b241569f95fb6d95727c24b19468813d596d5ae596 AS gops
ARG TARGETARCH
RUN apk add --no-cache binutils git \
 && git clone https://github.com/google/gops /go/src/github.com/google/gops \
 && cd /go/src/github.com/google/gops \
 && git checkout -b v0.3.27 v0.3.27 \
 && GOARCH=$TARGETARCH go build -ldflags="-s -w" .

# This builder (cross-)compile a stripped static version of bpftool.
# This step was kept because the downloaded version includes LLVM libs with the
# disassembler that makes the static binary grow from ~2Mo to ~30Mo.
FROM --platform=$BUILDPLATFORM quay.io/cilium/clang@sha256:b440ae7b3591a80ffef8120b2ac99e802bbd31dee10f5f15a48566832ae0866f AS bpftool-builder
WORKDIR /bpftool
ARG TARGETARCH BUILDARCH
RUN if [ $BUILDARCH != $TARGETARCH ]; \
    then apt-get update && echo "deb [arch=amd64] http://archive.ubuntu.com/ubuntu jammy main restricted universe multiverse\n\
deb [arch=amd64] http://security.ubuntu.com/ubuntu jammy-updates main restricted universe multiverse\n\
deb [arch=amd64] http://security.ubuntu.com/ubuntu jammy-security main restricted universe multiverse\n\
deb [arch=amd64] http://archive.ubuntu.com/ubuntu jammy-backports main restricted universe multiverse\n\
deb [arch=arm64] http://ports.ubuntu.com/ jammy main restricted universe multiverse\n\
deb [arch=arm64] http://ports.ubuntu.com/ jammy-updates main restricted universe multiverse\n\
deb [arch=arm64] http://ports.ubuntu.com/ jammy-security main restricted universe multiverse\n\
deb [arch=arm64] http://ports.ubuntu.com/ jammy-backports main restricted universe multiverse" > /etc/apt/sources.list \
    && dpkg --add-architecture arm64; fi
RUN apt-get update
RUN if [ $BUILDARCH != $TARGETARCH ]; \
    then apt-get install -y curl git llvm gcc pkg-config zlib1g-dev libelf-dev libelf-dev:arm64 libcap-dev:arm64 crossbuild-essential-$TARGETARCH; \
    else apt-get install -y curl git llvm gcc pkg-config zlib1g-dev libelf-dev libcap-dev; fi
# v7.1.0
ENV BPFTOOL_REV="b01941c8f7890489f09713348a7d89567538504b"
RUN git clone https://github.com/libbpf/bpftool.git . && git checkout ${BPFTOOL_REV} && git submodule update --init --recursive
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
FROM docker.io/library/alpine:3.21.2@sha256:56fa17d2a7e7f168a043a2712e63aed1f8543aeafdcee47c58dcffe38ed51099 AS base-build
RUN apk add --no-cache iproute2
RUN addgroup hubble	       && \
    mkdir /var/lib/tetragon/ && \
    mkdir /var/run/tetragon/ && \
    mkdir libs		       && \
    mkdir -p /etc/tetragon/tetragon.conf.d/ && \
    mkdir -p /etc/tetragon/tetragon.tp.d/ && \
    apk add --no-cache --update bash
RUN apk upgrade --no-cache
COPY --from=tetragon-builder /go/src/github.com/isovalent/hubble-fgs/tetragon /usr/bin/
COPY --from=tetragon-builder /go/src/github.com/isovalent/hubble-fgs/tetra /usr/bin/
COPY --from=gops /go/src/github.com/google/gops/gops /usr/bin/
COPY --from=bpf-builder /go/src/github.com/isovalent/hubble-fgs/bpf/objs/*.o /var/lib/tetragon/
COPY --from=tetragon-builder /go/src/github.com/isovalent/hubble-fgs/bpf/objs/tetragon-fs-scanner /var/lib/tetragon/
COPY --from=tetragon-builder /go/src/github.com/isovalent/hubble-fgs/bpf/objs/tetragon-runner /var/lib/tetragon/
COPY --from=tetragon-builder /go/src/github.com/isovalent/hubble-fgs/tetragon-oci-hook /usr/bin/
COPY --from=tetragon-builder /go/src/github.com/isovalent/hubble-fgs/tetragon-oci-hook-setup /usr/bin/
# legacy aliases
RUN ln -s /usr/bin/tetra /usr/bin/hubble-fgs-printer
RUN ln -s /usr/bin/tetra /usr/bin/hubble-enterprise
RUN ln -s /usr/bin/tetragon /usr/bin/hubble-fgs
ENTRYPOINT ["/usr/bin/tetragon"]

# This target only builds with the `--target release` option and reduces the
# size of the final image with a static build of bpftool without the LLVM
# disassembler
FROM base-build AS release
COPY --from=bpftool-builder bpftool/src/bpftool /usr/bin/bpftool

FROM base-build
COPY --from=bpftool-downloader /bpftool /usr/bin/bpftool
