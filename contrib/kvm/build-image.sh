#!/bin/bash
set -xeu

CONF_DIR="$(realpath $(dirname "${BASH_SOURCE[0]}"))"
source "$CONF_DIR/conf"
cd "$CONF_DIR"

DOCKER="${DOCKER:-docker}"
DOCKER_IMAGE="${DOCKER_IMAGE:-kvm-builder}"
RUN_FLAGS="${RUN_FLAGS:-}"
RUN_CMD="${RUN_CMD:-}"
PUBKEY="${PUBKEY:-"$HOME/.ssh/id_rsa.pub"}"

if [ -f "$ROOTIMG" ]; then
    set +x
    echo "file $ROOTIMG already exists. Bailing out" 1>&2
    exit 1
fi

cp "$PUBKEY" ./id_rsa.pub

mkdir -p "$MNTDIR"
mkdir -p "$(dirname "$ROOTIMG")"
truncate -s "$VMDISK" "$ROOTIMG"
mkfs.ext4 -q "$ROOTIMG"
sudo mount -o loop "$ROOTIMG" "$MNTDIR"
cleanup() {
	sudo umount "$MNTDIR" &>/dev/null
    rm -f ./id_rsa.pub
}
trap cleanup EXIT

$DOCKER build -t "$DOCKER_IMAGE" -f Dockerfile.kvm .
$DOCKER run -it --rm -v "$(realpath "$KOUT"):/kout" -v "$(realpath "$MNTDIR"):/mnt" $RUN_FLAGS "$DOCKER_IMAGE" $RUN_CMD
