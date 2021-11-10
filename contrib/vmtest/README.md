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

## What gets run

The init script created by the run.sh script will run two tools:

- fgs-verify-programs:
    A simple script that will use bpftool to load each FGS bpf object file
    and extract some useful stats (or the verifier error). Output looks like
    this:
    ```
         Verifying /var/lib/hubble-fgs/bpf_skmsg.o...
	 OK:
         ; int bpf_sk_msg_fgs(struct sk_msg_md *skmsg)
         verification time 2663524 usec
         stack depth 200
         processed 93226 insns (limit 1000000) max_states_per_insn 16 total_states 7809 peak_states 1497 mark_read 202
    ```

    This script can also be run locally with `make hubble-bpf-verify`.

- fgs-bench:
    The FGS benchmark tool that runs FGS alongside some load. See
    BENCHMARK.md for more info.

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
	contrib/vmtest/run.sh /tmp/bpf-next-kbuild \
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

## BPF latest nightly tests

We're running fgs-bench every night with the workflow defined in
`.github/workflows/bpf-nightly.yml`. This script shells out to
`contrib/vmtest/test-bpf-latest.sh`, which downloads and builds the
latest bpf tree and then runs the test with the scripts mentioned here.

This script can also be run locally by invoking `contrib/vmtest/test-bpf-latest.sh`
directly. It'll create `ksrc` and `kbuild` directories and build a new rootfs image.

