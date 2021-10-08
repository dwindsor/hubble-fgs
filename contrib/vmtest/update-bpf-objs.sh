#!/usr/bin/env bash
set -eu

OUT="fgs-bench-rootfs-$(date +%Y%m%d)-$(git rev-parse --short HEAD)"
IMG="${OUT}.img"

if [ ! -f $IMG ]; then
	echo "$IMG does not exist, run build-rootfs.sh first!"
	exit 1
fi

PATH=$PWD/bin:$PATH make -C bpf

set +e
mkdir -p mnt
sudo mount -o loop $IMG mnt
sudo cp -v bpf/objs/*.o mnt/var/lib/hubble-fgs/
sudo umount mnt

