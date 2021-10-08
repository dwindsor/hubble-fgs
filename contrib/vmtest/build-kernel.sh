#!/usr/bin/bash
set -eu

if [ $# -ne 2 ]; then
	echo "usage: $0 <kernel sources> <kbuild output>"
	exit 1
fi

if [ ! -f "$1/Kbuild" ]; then
	echo "$1 does not appear to be a kernel source tree"
	exit 1
fi

if [ ! -d $2 ]; then
	echo "Creating kbuild output directory '$2'..."
	mkdir -p $2
fi

KSRC=$1
KOUT=$2
SELFDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
NCPU=$(nproc)
MAKECMD="make --silent -j $NCPU -C $KSRC KCONFIG_CONFIG=${KOUT}/config KBUILD_OUTPUT=$KOUT"

set -x

cp "${SELFDIR}/kernel.config" "${KOUT}/config"
$MAKECMD olddefconfig
$MAKECMD

ls -l $KOUT/arch/x86/boot/bzImage
