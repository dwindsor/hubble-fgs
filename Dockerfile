FROM quay.io/isovalent/hubble-llvm:2020-12-29-45f6aa2 as bpf-builder
WORKDIR /go/src/github.com/isovalent/hubble-fgs
RUN apt-get update
RUN apt-get install -y linux-libc-dev
COPY . ./
RUN make hubble-bpf

FROM quay.io/isovalent/hubble-libbpf:v0.2.3 as hubble-libbpf
WORKDIR /go/src/github.com/isovalent/hubble-fgs
COPY . ./

FROM quay.io/cilium/cilium-builder:309d6c32ce304efe7490876be24804622f698999 as hubble-builder
WORKDIR /go/src/github.com/isovalent/hubble-fgs
COPY --from=hubble-libbpf /go/src/github.com/covalentio/hubble-fgs/src/libbpf.so.0.2.0 /usr/local/lib/
COPY --from=hubble-libbpf /go/src/github.com/covalentio/hubble-fgs/src/libbpf.so.0 /usr/local/lib/
COPY --from=hubble-libbpf /go/src/github.com/covalentio/hubble-fgs/src/libbpf.so /usr/local/lib/
COPY --from=hubble-libbpf /go/src/github.com/covalentio/hubble-fgs/src/libbpf.a /usr/local/lib/
RUN ldconfig /usr/local/; export LD_LIBRARY_PATH=/usr/local/lib/
COPY . ./
RUN make hubble-fgs-image

FROM docker.io/library/golang:1.17.3-alpine3.13 as gops
RUN apk add --no-cache binutils git \
 && git clone https://github.com/google/gops /go/src/github.com/google/gops \
 && cd /go/src/github.com/google/gops \
 && git checkout -b v0.3.22 v0.3.22 \
 && go install \
 && strip /go/bin/gops

FROM docker.io/library/alpine:3.12
RUN addgroup hubble	       && \
    mkdir /var/lib/hubble-fgs/ && \
    mkdir /var/run/hubble-fgs/ && \
    mkdir libs		       && \
    apk add --no-cache --update bash
COPY --from=hubble-builder /go/src/github.com/isovalent/hubble-fgs/hubble-fgs /usr/bin/
COPY --from=hubble-builder /go/src/github.com/isovalent/hubble-fgs/hubble-enterprise /usr/bin/
COPY --from=gops /go/bin/gops /bin /usr/bin/
COPY --from=bpf-builder /go/src/github.com/isovalent/hubble-fgs/bpf/objs/*.o /var/lib/hubble-fgs/
COPY --from=hubble-libbpf /go/src/github.com/covalentio/hubble-fgs/src/libbpf.so.0.2.0 /usr/local/lib/
COPY --from=hubble-libbpf /go/src/github.com/covalentio/hubble-fgs/src/libbpf.so.0 /usr/local/lib/
COPY --from=hubble-libbpf /go/src/github.com/covalentio/hubble-fgs/src/libbpf.so /usr/local/lib/
COPY --from=hubble-libbpf /go/src/github.com/covalentio/hubble-fgs/src/libbpf.a /usr/local/lib/
RUN ln -s /usr/bin/hubble-enterprise /usr/bin/hubble-fgs-printer
CMD ["sh", "-c", "/usr/bin/hubble-fgs --procfs=/procRoot/"]
