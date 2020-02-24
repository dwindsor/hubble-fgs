FROM quay.io/isovalent/hubble-llvm:2020-02-24 as bpf-builder
WORKDIR /go/src/github.com/covalentio/hubble-fgs
COPY . ./
RUN apt update
RUN apt install -y linux-libc-dev
RUN make hubble-bpf

FROM quay.io/cilium/cilium-builder:2019-09-04 as hubble-builder
WORKDIR /go/src/github.com/covalentio/hubble-fgs
COPY . ./
RUN make hubble-fgs-image

FROM docker.io/library/alpine:3.10
RUN addgroup hubble && mkdir /var/lib/hubble-fgs/ && mkdir /var/run/hubble-fgs/ \
 && apk add --no-cache bash curl jq
COPY --from=hubble-builder /go/src/github.com/covalentio/hubble-fgs/hubble-fgs /usr/bin/
COPY --from=hubble-builder /go/src/github.com/covalentio/hubble-fgs/hubble-fgs-printer /usr/bin/
COPY --from=hubble-builder /go/src/github.com/covalentio/hubble-fgs/libs/libbpf.so.0 /usr/lib/
COPY --from=bpf-builder /go/src/github.com/covalentio/hubble-fgs/bpf/*.o /var/lib/hubble-fgs/
CMD ["sh", "-c", "/usr/bin/hubble-fgs --procfs=/procRoot/ --bpf-execveat=/var/lib/hubble-fgs/bpf_execveat.o --bpf-execve=/var/lib/hubble-fgs/bpf_execve.o --bpf-fork=/var/lib/hubble-fgs/bpf_fork.o --bpf-tcpmon=/var/lib/hubble-fgs/bpf_tcpmon.o --bpf-tcpmonret=/var/lib/hubble-fgs/bpf_tcpmonret.o --bpf-bind=/var/lib/hubble-fgs/bpf_bind.o --bpf-get-port=/var/lib/hubble-fgs/bpf_get_port.o --bpf-listen=/var/lib/hubble-fgs/bpf_listen.o --btf=/var/lib/hubble-fgs/btf/btf"]
