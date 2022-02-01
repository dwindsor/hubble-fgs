#!/bin/bash

FGS_DIR=$(realpath $(dirname $0)/..)

CONTAINER_REPO="isovalent"
CONTAINER_FGS="${CONTAINER_REPO}/hubble-fgs"
CONTAINER_TEST="${CONTAINER_REPO}/hubble-fgs-test"
CONTAINER_DEV="${CONTAINER_REPO}/hubble-fgs-dev"
CONTAINER_NAME="kata-fgs"

btf="/var/lib/kata-containers/images/btf"
container="isovalent/hubble-fgs"
opt_test=0

usage() {
    echo "Usage: $0 [-h] [-d|-t|-c <container>] [-s|-e] [-l] [-D]"
    echo "Options:"
    echo "  -h: help"

    echo "  -d: use dev container ($CONTAINER_DEV)"
    echo "  -t: use test container ($CONTAINER_TEST)"
    echo "  -c: specify which container to run as argument"

    echo "  -s: run a shell"
    echo "  -x: run whatever comes after arguments"
    echo "  -e: exec inside container"

    echo "  -l: mount local dir inside container"

    echo "  -D: print commands of this script"

}

container=${CONTAINER_FGS}
docker_volumes="-v /proc:/procRoot"

while getopts "hdtc:sexlDb:" opt; do
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
        c)
            container=${OPTARG}
            ;;
        b)
           btf=${OPTARG}
           ;;
        s)
            opt_shell=true
            ;;
        e)
            opt_exec=true
            ;;
        x)
           opt_arg=true
           ;;
        l)
           docker_volumes="$docker_volumes -v ${FGS_DIR}:/go/src/github.com/isovalent/hubble-fgs"
           ;;

        D)
            set -x
            ;;
        *)
            echo "Invalid option: $opt"
            exit 1
    esac
done


KATA_RUNTIME=$(docker -D info | grep Runtimes: | grep -o 'kata[^ ]*')
if [ -z "$KATA_RUNTIME" ]; then
    echo "Cannot find kata runtime. Bailing out."
    exit 1
else
    echo "Using $KATA_RUNTIME as kata runtime"
fi

docker_volumes="$docker_volumes -v ${btf}:/var/lib/hubble-fgs/btf"

shift $(expr $OPTIND - 1)
if [ "$opt_exec" = true ]; then
    set -x
    docker exec -it kata-fgs bash
    exit
elif [ "$opt_arg" = true ]; then
    container_cmd="$@"
elif [ "$opt_shell" = true ]; then
    container_cmd="bash"
    if [ -f "$FGS_DIR/.bashrc-fgs" ]; then
        container_cmd="$container_cmd --rcfile .bashrc-fgs"
    fi
fi

docker run \
    --runtime=$KATA_RUNTIME \
    --cap-add all \
    --rm \
    -ti \
    --ulimit memlock=-1:-1 \
    --name $CONTAINER_NAME \
    $docker_volumes \
    $container \
    $container_cmd
