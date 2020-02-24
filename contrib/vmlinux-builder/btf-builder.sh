mkdir .btf
set -e
pushd .btf
wget $1
ar -x linux-image*
tar -xvf data.tar.xz
pahole -J ./usr/lib/debug/boot/*
llvm-objcopy --dump-section .BTF=.btf.vmlinux.bin ./usr/lib/debug/boot/*
llvm-objcopy -I binary -O elf64-x86-64 --rename-section .data=.BTF ./.btf.vmlinux.bin ../btf
