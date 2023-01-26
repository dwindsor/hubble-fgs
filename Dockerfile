FROM quay.io/cilium/clang:7ea8dd5b610a8864ce7b56e10ffeb61030a0c50e@sha256:02ad7cc1d08d85c027557099b88856945be5124b5c31aeabce326e7983e3913b as bpf-builder
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

# Mostly copied from https://github.com/cilium/image-tools/blob/master/images/bpftool
FROM quay.io/cilium/image-compilers:c1ba0665b6f9f012d014a642d9882f7c38bdf365@sha256:01c7c957e9b0fc200644996c6bedac297c98b81dea502a3bc3047837e67a7fcb as bpftool-builder
ENV REV "5e22dd18626726028a93ff1350a8a71a00fd843d"
RUN curl --fail --show-error --silent --location "https://kernel.googlesource.com/pub/scm/linux/kernel/git/bpf/bpf-next/+archive/${REV}.tar.gz" --output /tmp/linux.tgz
RUN mkdir -p /src/linux
RUN tar -xf /tmp/linux.tgz -C /src/linux
RUN rm -f /tmp/linux.tgz
WORKDIR /src/linux/tools/bpf/bpftool
RUN make -j $(nproc) LDFLAGS=-static
RUN strip bpftool

FROM docker.io/library/alpine:3.17.1@sha256:f271e74b17ced29b915d351685fd4644785c6d1559dd1f2d4189a5e851ef753a
RUN apk add iproute2
RUN addgroup hubble	       && \
    mkdir /var/lib/hubble-fgs/ && \
    mkdir /var/run/tetragon/ && \
    mkdir libs		       && \
    apk add --no-cache --update bash
COPY --from=bpftool-builder /src/linux/tools/bpf/bpftool/bpftool /usr/bin/bpftool
COPY --from=hubble-builder /go/src/github.com/isovalent/hubble-fgs/hubble-fgs /usr/bin/
COPY --from=hubble-builder /go/src/github.com/isovalent/hubble-fgs/hubble-enterprise /usr/bin/
COPY --from=gops /go/bin/gops /bin /usr/bin/
COPY --from=bpf-builder /go/src/github.com/isovalent/hubble-fgs/bpf/objs/*.o /var/lib/hubble-fgs/
COPY --from=hubble-builder /go/src/github.com/isovalent/hubble-fgs/bpf/objs/hubble-fgs-fs-scanner /var/lib/hubble-fgs/
RUN ln -s /usr/bin/hubble-enterprise /usr/bin/hubble-fgs-printer
CMD ["sh", "-c", "/usr/bin/hubble-fgs"]
