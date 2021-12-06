#!/usr/bin/env bash
#
# Run fgs-bench in a qemu-kvm virtual machine using the specified kernel image
#

set -e

if [ $# -lt 3 ]; then
	echo "usage: vmtest.sh <KOUT> <ROOTFS> <FGS BENCH ARGS>..."
	exit 1
fi

KOUT=$1
IMAGE=$2
shift 2
FGS_BENCH_ARGS="$*"

if [ ! -f "${KOUT}/bzImage" ]; then
	echo "Kernel not found from ${KOUT}/bzImage"
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

echo "Creating init script..."
mkdir -p mnt
sudo umount mnt || true
sudo mount -o loop $IMAGE mnt
sudo tee mnt/init.sh >/dev/null <<EOF
#!/bin/sh
trap sync EXIT
echo 130 > /exit-status
set -eux
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t bpf none /sys/fs/bpf
mount -t debugfs debugfs /sys/kernel/debug
mount -t tracefs tracefs /sys/kernel/debug/tracing
echo 7 > /proc/sys/kernel/printk
cat /sys/kernel/debug/tracing/trace_pipe &
ip addr add dev lo 127.0.0.1/8
ip link set dev lo up
/usr/bin/fgs-verify-programs
/usr/bin/parsertest -test.v -test.parallel 1
/usr/bin/fgs-bench $FGS_BENCH_ARGS
echo "\$?" > /exit-status
poweroff -f
EOF
sudo chmod +x mnt/init.sh

sudo cp "${KOUT}/bpftool" mnt/bin
sudo umount mnt

echo "Starting VM..."

KVMARGS=""
if [ -a /dev/kvm ]; then
	KVMARGS="-cpu kvm64 -enable-kvm"
fi

qemu-system-x86_64 \
	-nodefaults -display none -serial mon:stdio \
	-smp 4 -m 8G -no-reboot \
	-drive file=$IMAGE,format=raw,index=1,media=disk,if=virtio,cache=none \
	-kernel "${KOUT}/bzImage" \
	-append "root=/dev/vda rw loglevel=4 console=ttyS0,115200 panic=-1 init=/init.sh" \
	$KVMARGS

sudo mount -o loop $IMAGE mnt
EXITSTATUS="$(cat mnt/exit-status)"
sudo umount mnt
exit $EXITSTATUS
