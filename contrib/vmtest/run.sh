#!/usr/bin/env bash
#
# Run fgs-bench in a qemu-kvm virtual machine using the specified kernel image
#

set -e

if [ $# -lt 3 ]; then
	echo "usage: vmtest.sh <KERNEL> <ROOTFS> <FGS BENCH ARGS>..."
	exit 1
fi

KERNEL=$1
IMAGE=$2
shift 2
FGS_BENCH_ARGS="$*"

if [ ! -f "$KERNEL" ]; then
	echo "Kernel $KERNEL not found"
	exit 1
fi

if [ ! -f "$IMAGE" ]; then
	echo "Image $IMAGE not found"
	exit 1
fi

cleanup() {
	sudo umount mnt &> /dev/null
}
trap cleanup EXIT

echo "Creating init script:"
mkdir -p mnt
sudo mount -o loop $IMAGE mnt
sudo tee mnt/init.sh <<EOF
#!/bin/sh
echo 130 > /exit-status
set -eux
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t debugfs debugfs /sys/kernel/debug
mount -t tracefs tracefs /sys/kernel/debug/tracing
cat /sys/kernel/debug/tracing/trace_pipe &
ip addr add dev lo 127.0.0.1/8
ip link set dev lo up
/usr/bin/fgs-bench $FGS_BENCH_ARGS
echo "\$?" > /exit-status
poweroff -f
EOF
sudo chmod +x mnt/init.sh
sudo umount mnt

echo "Starting VM..."

KVMARGS=""
if [ -a /dev/kvm ]; then
	KVMARGS="-cpu kvm64 -enable-kvm"
fi

qemu-system-x86_64 \
	-nodefaults -display none -serial mon:stdio \
	-smp 4 -m 2G -no-reboot \
	-drive file=$IMAGE,format=raw,index=1,media=disk,if=virtio,cache=none \
	-kernel $KERNEL \
	-append "root=/dev/vda rw console=ttyS0,115200 panic=-1 init=/init.sh" \
	$KVMARGS

sudo mount -o loop $IMAGE mnt
EXITSTATUS="$(cat mnt/exit-status)"
sudo umount mnt
exit $EXITSTATUS
