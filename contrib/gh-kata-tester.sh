#!/bin/bash

FGS_DIR=$(realpath $(dirname $0)/..)

if [ -z "$KATA_IMG" ]; then
    echo "Please specify the kata-img script via the \$KATA_IMG env variable"
    exit 1
fi

if [ -z "$1" ]; then
    echo "Please specify the kernel version as the first argument"
    echo "Available-kernels:"
    $KATA_IMG
    exit 1
fi

set -o pipefail
ver=$($KATA_IMG | grep $1 | sort -V | tail -1)

if [ $? != 0 ]; then
    echo "Kernel $1 not found"
    echo "Available-kernels:"
    $KATA_IMG
    exit 1
fi

if [ -z "$2" ]; then
    echo "Please specify the docker image as the second argument"
    exit 1
else
    dockerimage=$2
fi



echo "Using kernel $ver for $1"
sudo $KATA_IMG $ver

set -e

tmpdir="${FGS_DIR}/logs/kata-tester-${ver}"
mkdir -p $tmpdir

sudo $FGS_DIR/contrib/kata-runner.sh -T $tmpdir -c $dockerimage -x './go-tests/observer.test -test.v -hubble-lib /var/lib/hubble-fgs/'
sudo $FGS_DIR/contrib/kata-runner.sh -T $tmpdir -c $dockerimage -x './go-tests/sockmap.test -test.v -hubble-lib /var/lib/hubble-fgs/'
