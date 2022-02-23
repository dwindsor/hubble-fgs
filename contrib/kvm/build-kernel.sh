#!/bin/bash

set -xeu

CONF_DIR="$(realpath $(dirname "${BASH_SOURCE[0]}"))"
source "$CONF_DIR/conf"
cd "$CONF_DIR"

KERNELURL="${KERNELURL:-""}"
KSRCDIR="${KSRCDIR:-""}"

# Use user-provided kernel source directory if it exists
if [ -d "$KSRCDIR" ]; then
    echo "Using user-provided KSRCDIR=$KSRCDIR" 1>&2
# Download latest kernel from the bpf tree if no source was manually supplied
elif [ ! -z "$KERNELURL" ]; then
    KERNELNAME="$(basename "$KERNELURL")"
    KERNELNAME="${KERNELNAME%.tar.*}"

    mkdir -p .ksrc
    KSRCDIR="$(realpath .ksrc)/$KERNELNAME"
    CURLOUT="$(mktemp)"

    mkdir -p "$KSRCDIR"
    # NOTE: we have to save the tarball because auto decompression doesn't work from stdin
    curl -sL "$KERNELURL" >"$CURLOUT"
    # TODO strip-components is needed for tarballs from the official linux mirrors, but
    # might break for other sources... probably need something more resilient down the road
    tar xfa "$CURLOUT" --strip-components=1 -C "$KSRCDIR"
    rm -f "$CURLOUT"

# Fall back to BPF latest
else
    KTREE="${1:-"bpf/bpf"}"
    KCOMMIT="${2:-"$(curl -sL "https://kernel.googlesource.com/pub/scm/linux/kernel/git/$KTREE.git/+/refs/heads/master?format=JSON" | sed 1d | jq -r .commit)"}"
    mkdir -p .ksrc
    KSRCDIR="$(realpath .ksrc)/bpf"

    if [ -d "$KSRCDIR" ]; then
        echo "KSRCDIR already exists, skipping download!" 1>&2
    else
        # NOTE: Using kernel.googlesource.com instead of git.kernel.org to reduce the load on kernel.org.
        # kernel.googlesource.com JSON output has a corrupted first line, hence the "sed 1d". We might need to change this if it gets fixed.
        # format=TEXT would've been nicer, but it doesn't list the commit and it's base64 encoded as well. Wonderful software.
        echo "Fetching commit $KTREE@$KCOMMIT..." 1>&2
        mkdir -p "$KSRCDIR"
        curl -sL "https://kernel.googlesource.com/pub/scm/linux/kernel/git/$KTREE.git/+archive/$KCOMMIT.tar.gz" | tar xz -C "$KSRCDIR"
    fi

fi

mkdir -p "$KOUT"
MODULESDIR="$(realpath "$MODULESDIR")"
NCPU="${NCPU:-"$(nproc)"}"
MAKECMD="make -j $NCPU -C $KSRCDIR"

cp "$KCONFIG" "$KSRCDIR/.config"
$MAKECMD olddefconfig
$MAKECMD
$MAKECMD INSTALL_MOD_PATH="$MODULESDIR" modules_install
cp "$KSRCDIR/arch/x86/boot/bzImage" "$KOUT/bzImage"

if command -v pahole &>/dev/null; then
    echo "Generating BTF info..."
    pahole --btf_encode_detached="$KOUT/vmlinux" "$KSRCDIR/vmlinux"
else
    echo "Pahole not installed, skipping BTF info generation..."
fi

MAKECMD="make -j $NCPU -C $KSRCDIR/tools/bpf/bpftool LDFLAGS=-static"
$MAKECMD
cp "$KSRCDIR/tools/bpf/bpftool/bpftool" "$KOUT/bpftool"
