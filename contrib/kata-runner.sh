#!/bin/bash

FGS_DIR=$(realpath $(dirname $0)/..)
BTF="/var/lib/kata-containers/images/btf"

CONTAINER_REPO="covalentio"
CONTAINER_FGS="${CONTAINER_REPO}/hubble-fgs"
CONTAINER_TEST="${CONTAINER_REPO}/hubble-fgs-test"
CONTAINER_DEV="${CONTAINER_REPO}/hubble-fgs-dev"
CONTAINER_CMD=""
CONTAINER_NAME="kata-fgs"

container="covalentio/hubble-fgs"
opt_test=0

usage() {
    echo "Usage: $0 [-h] [-t] [-s] [-d]"
    echo "Options:"
    echo "  -h: help"
    echo "  -t: use test container ($CONTAINER_TEST)"
    echo "  -d: use dev container ($CONTAINER_DEV)"
    echo "  -e: exec inside $CONTAINER_NAME"
    echo "  -d: debug (print commands)"
    echo "  -s: run a shell"
}

set -e

container=${CONTAINER_FGS}
while getopts "htsde" opt; do
    case $opt in
        h)
            usage
            exit 0
            ;;
        t)
            container=${CONTAINER_TEST}
            ;;
        d)
            container=${CONTAINER_DEV}
            ;;
        s)
            opt_shell=true
            ;;
        e)
            opt_exec=true
            ;;

        d)
            set -x
            ;;
        *)
            echo "Invalid option: $opt"
            exit 1
    esac
done


if [ "$opt_exec" = true ]; then
    set -x
    docker exec -it kata-fgs bash
    exit
fi

if [ "$opt_shell" = true ]; then
    container_cmd="bash"
    if [ -f "$FGS_DIR/.bashrc-fgs" ]; then
        container_cmd="$container_cmd --rcfile .bashrc-fgs"
    fi
fi

# -v ${FGS_DIR}:/go/src/github.com/covalentio/hubble-fgs \


docker run \
    --runtime=kata-runtime \
    --cap-add all \
    --rm \
    -ti \
    --ulimit memlock=-1:-1 \
    --runtime=kata-runtime \
    --name $CONTAINER_NAME \
    -v /proc:/procRoot \
    -v ${BTF}:/var/lib/hubble-fgs/btf \
    $container \
    $container_cmd
