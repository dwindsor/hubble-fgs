#!/bin/bash
BPF_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

mkdir bins
for d in `find ${BPF_DIR}/include/ -type d | awk '{if(NR>1)print}'`; do
	make -C ${BPF_DIR} clean
	dir=`echo $d | awk 'BEGIN { FS = "/" } ; {print $NF}';` 
	echo "dir ${dir}"
	cp ${BPF_DIR}/include/${dir}/vmlinux.h ${BPF_DIR}/
	echo "cp ${BPF_DIR}/include/${dir}/vmlinux.h ${BPF_DIR}/"
	make -C ${BPF_DIR}
	cp ${BPF_DIR}/bpf_tcpmon.o ${BPF_DIR}/bins/bpf_tcpmon_${dir}.o
	cp ${BPF_DIR}/bpf_tcpmonret.o ${BPF_DIR}/bins/bpf_tcpmonret_${dir}.o
	cp ${BPF_DIR}/bpf_execve.o ${BPF_DIR}/bins/bpf_execve_${dir}.o
	cp ${BPF_DIR}/bpf_execveat.o ${BPF_DIR}/bins/bpf_execveat_${dir}.o
	echo "cp ${BPF_DIR}/bpf_execve.o ${BPF_DIR}/bins/bpf_execve_${dir}.o"
done
make -C ${BPF_DIR} clean
