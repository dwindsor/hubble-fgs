#!/bin/bash
set -xeu

DOCKER="${DOCKER:-docker}"
DOCKER_IMAGE="${DOCKER_IMAGE:-kvm-builder}"

# cd into the parent dir
cd "$(realpath $(dirname "${BASH_SOURCE[0]}"))"/..

$DOCKER build -t "$DOCKER_IMAGE" -f Dockerfile.builder .
$DOCKER run --privileged -it --rm -v "$(realpath .):/host" "$DOCKER_IMAGE"
