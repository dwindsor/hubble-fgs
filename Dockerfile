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
FROM --platform=$BUILDPLATFORM quay.io/cilium/clang@sha256:b440ae7b3591a80ffef8120b2ac99e802bbd31dee10f5f15a48566832ae0866f as bpf-builder
WORKDIR /go/src/github.com/isovalent/hubble-fgs
RUN apt-get update && apt-get install -y linux-libc-dev
COPY . ./
ARG TARGETARCH
RUN make hubble-bpf LOCAL_CLANG=1 TARGET_ARCH=$TARGETARCH

# Second builder (cross-)compile:
# - hubble-fgs-fs-scanner (this one uses CGO, so a gcc cross compiler is needed)
# - hubble-fgs            (tetragon/pkg/bpf uses CGO, so a gcc cross compiler is needed)
# - hubble-enterprise
FROM --platform=$BUILDPLATFORM quay.io/cilium/cilium-builder:2460ae43ce9ab3ab0ff3a8b6e3bc434e6b58e9c0@sha256:97a6aa77af7f8fd5b2cff11ce2049a57e7debec4684652bd368f5911279da4bc as hubble-builder
WORKDIR /go/src/github.com/isovalent/hubble-fgs
ARG TARGETARCH BUILDARCH
RUN apt-get update
RUN if [ $BUILDARCH != $TARGETARCH ]; \
    then apt-get install -y libelf-dev zlib1g-dev crossbuild-essential-$TARGETARCH; \
    else apt-get install -y libelf-dev zlib1g-dev; fi
RUN apt-get update && apt-get install -y libelf-dev zlib1g-dev crossbuild-essential-$TARGETARCH
RUN ldconfig /usr/local/
COPY . ./
RUN if [ $BUILDARCH != $TARGETARCH ]; \
    then make hubble-fgs-image TARGET_ARCH=$TARGETARCH CC=aarch64-linux-gnu-gcc; \
    else make hubble-fgs-image TARGET_ARCH=$TARGETARCH; fi

# Third builder (cross-)compile a stripped gops
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.19.3-alpine3.15@sha256:eabc3aca6f6c4386369b5b067c9c210aeccd39e76907fa2f8f774fd59d83425a as gops
ARG TARGETARCH
RUN apk add --no-cache binutils git \
 && git clone https://github.com/google/gops /go/src/github.com/google/gops \
 && cd /go/src/github.com/google/gops \
 && git checkout -b v0.3.22 v0.3.22 \
 && GOARCH=$TARGETARCH go build -ldflags="-s -w" .

# Fourth builder (cross-)compile a stripped static version of bpftool
# This part should be a separated image, this is way too complicated
FROM --platform=$BUILDPLATFORM quay.io/cilium/clang@sha256:b440ae7b3591a80ffef8120b2ac99e802bbd31dee10f5f15a48566832ae0866f as bpftool-builder
WORKDIR /bpftool
ARG TARGETARCH BUILDARCH
RUN echo $BUILDARCH
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
ENV BPFTOOL_REV "b01941c8f7890489f09713348a7d89567538504b"
RUN git clone --recurse-submodules https://github.com/libbpf/bpftool.git . && git checkout ${BPFTOOL_REV}
RUN if [ $BUILDARCH != $TARGETARCH ]; \
    then make -C src EXTRA_CFLAGS=--static CC=aarch64-linux-gnu-gcc -j $(nproc) && aarch64-linux-gnu-strip src/bpftool; \
    else make -C src EXTRA_CFLAGS=--static -j $(nproc) && strip src/bpftool; fi

# Final step runs on target platform (might need emulation) and retrieves
# (cross-)compiled binaries from builders
FROM docker.io/library/alpine:3.17.2@sha256:ff6bdca1701f3a8a67e328815ff2346b0e4067d32ec36b7992c1fdc001dc8517
RUN apk add iproute2
RUN addgroup hubble	       && \
    mkdir /var/lib/hubble-fgs/ && \
    mkdir /var/run/tetragon/ && \
    mkdir libs		       && \
    apk add --no-cache --update bash
COPY --from=bpftool-builder /bpftool/src/bpftool /usr/bin/bpftool
COPY --from=hubble-builder /go/src/github.com/isovalent/hubble-fgs/hubble-fgs /usr/bin/
COPY --from=hubble-builder /go/src/github.com/isovalent/hubble-fgs/hubble-enterprise /usr/bin/
COPY --from=gops /go/src/github.com/google/gops/gops /usr/bin/
COPY --from=bpf-builder /go/src/github.com/isovalent/hubble-fgs/bpf/objs/*.o /var/lib/hubble-fgs/
COPY --from=hubble-builder /go/src/github.com/isovalent/hubble-fgs/bpf/objs/hubble-fgs-fs-scanner /var/lib/hubble-fgs/
RUN ln -s /usr/bin/hubble-enterprise /usr/bin/hubble-fgs-printer
CMD ["sh", "-c", "/usr/bin/hubble-fgs"]
