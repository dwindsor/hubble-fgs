FROM quay.io/cilium/clang@sha256:b440ae7b3591a80ffef8120b2ac99e802bbd31dee10f5f15a48566832ae0866f as bpf-builder
WORKDIR /go/src/github.com/isovalent/hubble-fgs
RUN apt-get update
RUN apt-get install -y linux-libc-dev
COPY . ./
RUN make hubble-bpf LOCAL_CLANG=1

FROM quay.io/cilium/cilium-builder:2460ae43ce9ab3ab0ff3a8b6e3bc434e6b58e9c0@sha256:97a6aa77af7f8fd5b2cff11ce2049a57e7debec4684652bd368f5911279da4bc as hubble-builder
WORKDIR /go/src/github.com/isovalent/hubble-fgs
RUN apt-get update && apt-get install -y libelf-dev zlib1g-dev
RUN ldconfig /usr/local/
COPY . ./
RUN make hubble-fgs-image

FROM docker.io/library/golang:1.19.3-alpine3.15@sha256:eabc3aca6f6c4386369b5b067c9c210aeccd39e76907fa2f8f774fd59d83425a as gops
RUN apk add --no-cache binutils git \
 && git clone https://github.com/google/gops /go/src/github.com/google/gops \
 && cd /go/src/github.com/google/gops \
 && git checkout -b v0.3.22 v0.3.22 \
 && go install \
 && strip /go/bin/gops

FROM quay.io/cilium/clang@sha256:b440ae7b3591a80ffef8120b2ac99e802bbd31dee10f5f15a48566832ae0866f as bpftool-builder
WORKDIR /bpftool
RUN apt-get update && apt-get install -y \
    curl git \
    llvm gcc pkg-config zlib1g-dev libelf-dev libcap-dev \
    && rm -rf /var/lib/apt/lists/*
# v7.1.0
ENV BPFTOOL_REV "b01941c8f7890489f09713348a7d89567538504b"
RUN git clone --recurse-submodules https://github.com/libbpf/bpftool.git . && git checkout ${BPFTOOL_REV}
RUN make -C src EXTRA_CFLAGS=--static -j $(nproc) && strip src/bpftool

FROM docker.io/library/alpine:3.17.2@sha256:69665d02cb32192e52e07644d76bc6f25abeb5410edc1c7a81a10ba3f0efb90a
RUN apk add iproute2
RUN addgroup hubble	       && \
    mkdir /var/lib/hubble-fgs/ && \
    mkdir /var/run/tetragon/ && \
    mkdir libs		       && \
    apk add --no-cache --update bash
COPY --from=bpftool-builder /bpftool/src/bpftool /usr/bin/bpftool
COPY --from=hubble-builder /go/src/github.com/isovalent/hubble-fgs/hubble-fgs /usr/bin/
COPY --from=hubble-builder /go/src/github.com/isovalent/hubble-fgs/hubble-enterprise /usr/bin/
COPY --from=gops /go/bin/gops /bin /usr/bin/
COPY --from=bpf-builder /go/src/github.com/isovalent/hubble-fgs/bpf/objs/*.o /var/lib/hubble-fgs/
COPY --from=hubble-builder /go/src/github.com/isovalent/hubble-fgs/bpf/objs/hubble-fgs-fs-scanner /var/lib/hubble-fgs/
RUN ln -s /usr/bin/hubble-enterprise /usr/bin/hubble-fgs-printer
CMD ["sh", "-c", "/usr/bin/hubble-fgs"]
