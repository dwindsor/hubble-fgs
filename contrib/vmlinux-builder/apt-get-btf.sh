apt update
apt install linux-image-unsigned-`uname -r`-dbgsym
docker run --name btf-build -v /lib/debug/boot:/kernels/ quay.io/isovalent/hubble-llvm:2020-03-04 /bin/bash -c \
"
	export LD_LIBRARY_PATH=/usr/local/lib/lib/ && \
	cd /kernels/ && \
	pahole -J vmlinux-`uname -r`
"
docker cp btf-build:/kernels/btf ./bpf/btf
docker rm -f btf-build
