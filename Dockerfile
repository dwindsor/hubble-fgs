FROM quay.io/isovalent/hubble-llvm:2020-12-29-45f6aa2 as bpf-builder
WORKDIR /go/src/github.com/covalentio/hubble-fgs
COPY . ./
RUN apt update
RUN apt install -y linux-libc-dev
RUN make hubble-bpf

FROM quay.io/isovalent/hubble-libbpf:v0.2.2 as hubble-libbpf
WORKDIR /go/src/github.com/covalentio/hubble-fgs
COPY . ./

FROM quay.io/cilium/cilium-builder:2020-12-15-v1.9 as hubble-builder
WORKDIR /go/src/github.com/covalentio/hubble-fgs
COPY . ./
COPY --from=hubble-libbpf /go/src/github.com/covalentio/hubble-fgs/src/libbpf.so.0.2.0 /usr/local/lib/
COPY --from=hubble-libbpf /go/src/github.com/covalentio/hubble-fgs/src/libbpf.so.0 /usr/local/lib/
COPY --from=hubble-libbpf /go/src/github.com/covalentio/hubble-fgs/src/libbpf.so /usr/local/lib/
COPY --from=hubble-libbpf /go/src/github.com/covalentio/hubble-fgs/src/libbpf.a /usr/local/lib/
RUN ldconfig /usr/local/; export LD_LIBRARY_PATH=/usr/local/lib/
RUN make hubble-fgs-image

FROM docker.io/library/golang:1.15.7-alpine as gops
RUN apk add --no-cache binutils git \
 && go get -d github.com/google/gops \
 && cd /go/src/github.com/google/gops \
 && git checkout -b v0.3.14 v0.3.14 \
 && go install \
 && strip /go/bin/gops

FROM docker.io/library/alpine:3.12
RUN addgroup hubble	       && \
    mkdir /var/lib/hubble-fgs/ && \
    mkdir /var/run/hubble-fgs/ && \
    mkdir libs		       && \
    apk add --no-cache --update bash curl jq
COPY --from=hubble-builder /go/src/github.com/covalentio/hubble-fgs/hubble-fgs /usr/bin/
COPY --from=hubble-builder /go/src/github.com/covalentio/hubble-fgs/hubble-enterprise /usr/bin/
COPY --from=gops /go/bin/gops /bin /usr/bin/
COPY --from=bpf-builder /go/src/github.com/covalentio/hubble-fgs/bpf/objs/*.o /var/lib/hubble-fgs/
COPY --from=hubble-libbpf /go/src/github.com/covalentio/hubble-fgs/src/libbpf.so.0.2.0 /usr/local/lib/
COPY --from=hubble-libbpf /go/src/github.com/covalentio/hubble-fgs/src/libbpf.so.0 /usr/local/lib/
COPY --from=hubble-libbpf /go/src/github.com/covalentio/hubble-fgs/src/libbpf.so /usr/local/lib/
COPY --from=hubble-libbpf /go/src/github.com/covalentio/hubble-fgs/src/libbpf.a /usr/local/lib/
RUN ln -s /usr/bin/hubble-enterprise /usr/bin/hubble-fgs-printer
CMD ["sh", "-c", "/usr/bin/hubble-fgs --procfs=/procRoot/"]
