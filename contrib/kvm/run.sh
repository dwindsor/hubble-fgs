#!/bin/bash

set -eu

CONF_DIR="$(realpath $(dirname "${BASH_SOURCE[0]}"))"
source $CONF_DIR/conf
cd "$CONF_DIR"

usage() {
	echo "usage: run.sh [OPTIONS]" 1>&2
	echo "OPTIONS:" 1>&2
    echo "    --kernel [KERNEL]  path to kernel bzImage (relative to run.sh or absolute)" 1>&2
    echo "    --disk   [IMAGE]   path to root filesystem image (relative to run.sh or absolute)" 1>&2
    echo "    --port   [NUMBER]  port to forward on the host for ssh access" 1>&2
    echo "    --foreground, --fg run in the foreground" 1>&2
}

while [ $# -ge 1 ]; do
	if [ "$1" == "--kernel" ]; then
		BZIMAGE="$2"
		shift 2
	elif [ "$1" == "--disk" ]; then
		ROOTIMG="$2"
		shift 2
	elif [ "$1" == "--foreground" ] || [ "$1" == "--fg" ] ; then
		FOREGROUND=1
		shift 1
	elif [ "$1" == "--port" ] ; then
		SSHPORT="$2"
		shift 2
    else
        usage
        exit 1
	fi
done

# Get absolute path to bzImage
BZIMAGE="$(realpath "$BZIMAGE")"

# Build up qemu options
declare -a qemu_opts=("-nodefaults" "-display" "none" "-no-reboot")
# CPUs and RAM
qemu_opts+=("-smp" "$VMCPUS" "-m" "$VMRAM")
# Root filesystem options
qemu_opts+=("-drive" "file=$ROOTIMG,format=raw,index=1,media=disk,if=virtio,cache=none")
# Kernel options
qemu_opts+=("-kernel" "$BZIMAGE")
qemu_opts+=("-append" "root=/dev/vda rw loglevel=4 console=ttyS0,115200 panic=-1")
# Network options
# For now, virtio-net-pci appears to be required in order for FGS's TC programs to work correctly
qemu_opts+=("-device" "virtio-net-pci,netdev=net0,mac=$MACADDR")
qemu_opts+=("-netdev" "type=user,id=net0,hostfwd=tcp::$SSHPORT-:22")
# Network share options
if [ -d "$MODULESDIR/lib/modules" ]; then
    MODULESDIR="$(realpath "$MODULESDIR")"
    mkdir -p $MODULESDIR
    qemu_opts+=("-fsdev" "local,id=fs1,path=$MODULESDIR/lib/modules,security_model=none")
    qemu_opts+=("-device" "virtio-9p-pci,fsdev=fs1,mount_tag=modules")
fi
if [ ! -z "$FGSDIR" ] && [ -d "$FGSDIR" ]; then
    FGSDIR="$(realpath "$FGSDIR")"
    qemu_opts+=("-fsdev" "local,id=fs2,path=$FGSDIR,security_model=none")
    qemu_opts+=("-device" "virtio-9p-pci,fsdev=fs2,mount_tag=fgs")
fi
# KVM options
if [ -a /dev/kvm ]; then
    qemu_opts+=("-cpu" "kvm64" "-enable-kvm")
fi

# Run in foreground if $FOREGROUND is set
if [ ! -z ${FOREGROUND+x} ]; then
    echo "Starting VM in foreground..." 1>&2
    qemu_opts+=("-serial" "mon:stdio")
else
    echo "Starting VM in background..." 1>&2
    qemu_opts+=("-daemonize")
fi

sudo qemu-system-x86_64 "${qemu_opts[@]}"
