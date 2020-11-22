apt update
echo "deb http://ddebs.ubuntu.com $(lsb_release -cs) main restricted universe multiverse
      deb http://ddebs.ubuntu.com $(lsb_release -cs)-updates main restricted universe multiverse
      deb http://ddebs.ubuntu.com $(lsb_release -cs)-proposed main restricted universe multiverse" | \
tee -a /etc/apt/sources.list.d/ddebs.list
apt install ubuntu-dbgsym-keyring
apt update
apt install linux-image-unsigned-`uname -r`-dbgsym
echo "debug images pulled"
echo `ls /usr/lib/debug/boot/`
echo "docker run and build"
docker run --name btf-build -v /usr/lib/debug/boot:/kernels/ quay.io/isovalent/hubble-llvm:2020-11-25-194d3985-x86 /bin/bash -c \
"
	export LD_LIBRARY_PATH=/usr/local/lib/lib/ && \
	cd /kernels/ && \
	pahole -J vmlinux-`uname -r` && \
	llvm-objcopy --dump-section .BTF=.btf.vmlinux.bin vmlinux-`uname -r` && \
	llvm-objcopy -I binary -O elf64-x86-64 --rename-section .data=.BTF ./.btf.vmlinux.bin ./btf
"
docker cp btf-build:/kernels/btf ./bpf/btf
docker rm -f btf-build
