FROM quay.io/cilium/cilium-builder:2019-09-04 as builder
WORKDIR /go/src/github.com/covalentio/hubble-fgs
COPY . ./
RUN make clean && make hubble-fgs-image

FROM docker.io/library/alpine:3.10
RUN addgroup hubble && mkdir /var/lib/hubble-fgs/ && mkdir /var/run/hubble-fgs/
COPY --from=builder /go/src/github.com/covalentio/hubble-fgs/hubble-fgs /usr/bin/
COPY --from=builder /go/src/github.com/covalentio/hubble-fgs/hubble-fgs-printer /usr/bin/
COPY --from=builder /go/src/github.com/covalentio/hubble-fgs/libs/libbpf.so.0 /usr/lib/
COPY --from=builder /go/src/github.com/covalentio/hubble-fgs/bpf/bins/* /var/lib/hubble-fgs/
CMD ["sh", "-c", "/usr/bin/hubble-fgs --procfs=/procRoot/ --bpf-execveat=/var/lib/hubble-fgs/bpf_execveat_`uname -r`.o --bpf-execve=/var/lib/hubble-fgs/bpf_execve_`uname -r`.o --bpf-fork=/var/lib/hubble-fgs/bpf_fork_`uname -r`.o --bpf-clone=/var/lib/hubble-fgs/bpf_fork_`uname -r`.o --bpf-vfork=/var/lib/hubble-fgs/bpf_fork_`uname -r`.o --bpf-tcpmon=/var/lib/hubble-fgs/bpf_tcpmon_`uname -r`.o --bpf-tcpmonret=/var/lib/hubble-fgs/bpf_tcpmonret_`uname -r`.o"]
