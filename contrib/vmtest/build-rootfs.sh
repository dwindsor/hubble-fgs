#!/usr/bin/env bash
set -eu

echo "Building fgs-bench docker image..."
IMAGEID=$(docker build . -q -f Dockerfile.bench)
CONTID=$(docker run -d $IMAGEID /bin/true)
OUT="fgs-bench-rootfs-$(date +%Y%m%d)-$(git rev-parse --short HEAD)"
IMG="${OUT}.img"

echo "Creating root filesystem..."
truncate -s 2G $IMG
mkfs.ext4 -q $IMG

mkdir -p mnt
sudo mount -o loop $IMG mnt
docker export $CONTID | sudo tar x -C mnt
sudo umount mnt
docker stop $CONTID

echo $IMG
