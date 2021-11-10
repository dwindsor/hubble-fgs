#!/bin/bash
set -eux

# Build the root filesystem.
contrib/vmtest/build-rootfs.sh

# Fetch and build the latest bpf kernel.
mkdir ksrc kbuild
# NOTE: Using kernel.googlesource.com instead of git.kernel.org to reduce the load on kernel.org.
# kernel.googlesource.com JSON output has a corrupted first line, hence the "sed 1d". We might need to change this if it gets fixed.
# format=TEXT would've been nicer, but it doesn't list the commit and it's base64 encoded as well. Wonderful software.
curl -sL 'https://kernel.googlesource.com/pub/scm/linux/kernel/git/bpf/bpf.git/+/refs/heads/master?format=JSON' | sed 1d > latest.json
KCOMMIT="$(jq -r .commit latest.json)"

: "Fetching bpf.git $KCOMMIT..."
curl -sL https://kernel.googlesource.com/pub/scm/linux/kernel/git/bpf/bpf.git/+archive/$KCOMMIT.tar.gz | tar xz -C ksrc
contrib/vmtest/build-kernel.sh $PWD/ksrc $PWD/kbuild

# Run fgs-bench in qemu-kvm with the latest bpf kernel.
contrib/vmtest/run.sh $PWD/kbuild $PWD/fgs-bench-rootfs*.img \
  -source tls-crr -sink tls-go -parsers=tls -duration=5m

