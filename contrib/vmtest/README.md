# Tooling for building and running fgs-bench in qemu-kvm VMs

This directory contains a set of tools for running fgs-bench in VMs:

- build-rootfs.sh: Build a root filesystem for running fgs-bench
- build-kernel.sh: Build a minimal Linux kernel image
- run.sh: Run fgs-bench with given kernel and rootfs image

These scripts should be run from the root of the hubble-fgs repository.

The root filesystem is built by first building the docker image as specified
in Dockerfile.bench and then copying it into a ext2 fs image.

The run.sh script updates the init script in the fs image and then runs it
using qemu-kvm.

## Bisecting a kernel issue

1. Build the root filesystem:

  hubble-fgs$ contrib/vmtest/build-rootfs.sh
  ...
  fgs-bench-rootfs-20210924-d38a0633.img

2. Create the bisecting test script to the root of the kernel source tree,
   for example:

  #!/bin/bash
  set -eux
  KSRC=$PWD
  IMG=fgs-bench-rootfs-20210924-d38a0633.img
  cd /home/$USER/src/hubble-fgs
  contrib/vmtest/build-kernel.sh $KSRC /tmp/bpf-next-kbuild
  contrib/vmtest/run.sh /tmp/bpf-next-kbuild/arch/x86/boot/bzImage \
    "$IMG" \
    -source tls-crr -sink tls-go -parsers=tls -duration=10s

3. Test the script on the bad and good commits

  bpf-next$ chmod +x bisect.sh
  bpf-next$ ./bisect.sh
  <FAIL>
  bpf-next$ git checkout v5.12
  bpf-next$ ./bisect.sh
  <SUCCEED>
 
4. Start bisecting

  bpf-next$ git bisect start
  bpf-next$ git bisect good v5.12
  bpf-next$ git bisect bad HEAD
  bpf-next$ git bisect run bisect.sh

## Known issues

The current version of the libbpf fork we're using does not support KIND_FLOAT,
so you might see "failed to parse BTF: 22" error. Fix coming soon.
