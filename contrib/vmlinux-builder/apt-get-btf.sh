#!/bin/bash

apt update
echo "deb http://ddebs.ubuntu.com $(lsb_release -cs) main restricted universe multiverse
      deb http://ddebs.ubuntu.com $(lsb_release -cs)-updates main restricted universe multiverse
      deb http://ddebs.ubuntu.com $(lsb_release -cs)-proposed main restricted universe multiverse" | \
tee -a /etc/apt/sources.list.d/ddebs.list
apt install ubuntu-dbgsym-keyring
## Quick fix for https://bugs.launchpad.net/ubuntu/+source/ubuntu-keyring/+bug/1920640
wget -O- http://ddebs.ubuntu.com/dbgsym-release-key.asc | sudo apt-key add -

apt update
k=`uname -r`
k="${k/1032/1031}"
apt install linux-image-unsigned-${k}-dbgsym
echo "debug images pulled"
echo `ls /usr/lib/debug/boot/`
echo "docker run and build"
docker run --name btf-build -v /usr/lib/debug/boot:/kernels/ quay.io/isovalent/hubble-llvm:2020-12-29-45f6aa2 /bin/bash -c \
"
	export LD_LIBRARY_PATH=/usr/local/lib/lib/ && \
	cd /kernels/ && \
	k=`uname -r` && \
	k="${k/1032/1031}" && \
	pahole -J vmlinux-${k} && \
	llvm-objcopy --dump-section .BTF=.btf.vmlinux.bin vmlinux-${k} && \
	llvm-objcopy -I binary -O elf64-x86-64 --rename-section .data=.BTF ./.btf.vmlinux.bin ./btf
"
mkdir -p ./bpf/objs
docker cp btf-build:/kernels/btf ./bpf/objs/btf
docker rm -f btf-build
