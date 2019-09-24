DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

mkdir bins
for d in `find ./include/ -type d | awk '{if(NR>1)print}'`; do 
	make clean
	dir=`echo $d | awk 'BEGIN { FS = "/" } ; {print $NF}';` 
	cp ./include/${dir}/vmlinux.h .
	make
	cp ./bpf_tcpmon.o ./bins/bpf_tcpmon_${dir}.o
	cp ./bpf_execve.o ./bins/bpf_execve_${dir}.o
done
make clean
