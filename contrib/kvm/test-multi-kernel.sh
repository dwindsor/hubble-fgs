#!/bin/bash

set -eu

CONF_DIR="$(realpath $(dirname "${BASH_SOURCE[0]}"))"
source $CONF_DIR/conf
cd "$CONF_DIR"

RUN_CMD="$CONF_DIR/run.sh"
SSH_CMD="$CONF_DIR/ssh.sh"
STOP_CMD="$CONF_DIR/stop.sh"

usage() {
	echo "usage: test-multi-kernel.sh --kernels <kernel1,kernel2,...,kernelN> [OPTIONS]" 1>&2
	echo "OPTIONS:" 1>&2
    echo "    --kernels [KERNEL]  comma-separated list of paths to kernel bzImage that should be tested" 1>&2
    echo "    --disk    [IMAGE]   path to root filesystem image" 1>&2
}

while [ $# -ge 1 ]; do
	if [ "$1" == "--kernels" ]; then
        IFS=','
        KERNELS=( $2 )
        IFS=' '
		shift 2
	elif [ "$1" == "--disk" ]; then
		ROOTIMG="$2"
		shift 2
    else
        usage
        exit 1
	fi
done

if [ -z "${KERNELS:+x}" ]; then
    usage
    exit 1
fi

trap '"$STOP_CMD" || true' EXIT

FGS_IMAGE_LOADED=0
BTF_FILE=""

for kernel in "${KERNELS[@]}"; do
    echo "Testing on kernel $kernel..." 1>&2
    "$RUN_CMD" --kernel "$kernel"
    if [ -f "$kernel".btf ]; then
        BTF_FILE="$(realpath "$kernel".btf)"
        echo "Auto-discovered BTF file $BTF_FILE" 1>&2
    fi
    if [ "$FGS_IMAGE_LOADED" == 0 ]; then
        pushd ../..
        echo "Building FGS image..." 1>&2
        make image
        if [ -f "$BTF_FILE" ]; then
            echo "Creating BTF symlink..." 1>&2
            ln -vsnfr "$BTF_FILE" bpf/objs/btf
            BTF_FILE=""
        fi
        popd
        echo "Loading FGS image into VM..." 1>&2
        docker save isovalent/hubble-fgs:latest | bzip2 | "$SSH_CMD" "docker load"
        FGS_IMAGE_LOADED=1
    fi
    "$SSH_CMD" <<- EOF
echo "Testing on Linux \$(uname -r)..." 1>&2
set -e
export PATH="\$PATH:/usr/local/go/bin"
cd /fgs

# Run unit tests
make test

# Run end-to-end-tests
contrib/end-to-end/bootstrap-cluster.sh
contrib/end-to-end/install-fgs.sh --image isovalent/hubble-fgs:latest
contrib/end-to-end/tests/http-tls.sh
contrib/end-to-end/tests/demo-app.sh
echo "Done testing on Linux \$(uname -r)!" 1>&2
EOF
    "$STOP_CMD"
done
