#!/usr/bin/env bash
SCRIPTDIR="$(dirname "${BASH_SOURCE[0]}")"
set -eu

echo "Building fgs-bench docker image..." 1>&2
IMAGEID=$(docker build . -q -f Dockerfile.bench)
CONTID=$(docker run -d $IMAGEID /bin/true)
IMG="fgs-bench-rootfs-$(date +%Y%m%d)-$(git rev-parse --short HEAD).img"

echo "Creating root filesystem..." 1>&2
truncate -s 2G $IMG
mkfs.ext4 -q $IMG

mkdir -p mnt
sudo mount -o loop $IMG mnt
docker export $CONTID | sudo tar x -C mnt
sudo cp "${SCRIPTDIR}/fgs-verify-programs" mnt/usr/bin
sudo umount mnt
docker stop $CONTID 1>&2

echo $IMG
