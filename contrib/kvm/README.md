# Little VM Helper Scripts for Testing Tetragon

This directory contains LVH (Little VM Helper) scripts that help to test Tetragon on
multiple kernels. These are exposed through a Makefile that has targets for installing
LVH, building a kernel, building a disk image, and spinning up a KVM virtual machine with
this kernel and disk image.

## Supported Kernels

Currently, these scripts ship with the following kernels supported by default:

- bpf-next
- 5.15
- 5.10
- 5.4
- 4.19

Should you wish to add a new kernel, you can do so with `make add-kernel KERNEL=name
KERNEL_URL=giturl`. Alternatively, you can run the `lvh` command directly or just edit
`_data/kernels.json`.

## Workflow

0. The first time you run this on your system, you will need to install LVH to your
   GOPATH. You can do this using `make install-lvh`.

1. Build your desired kernel. You can do this using `make build-kernel KERNEL=5.15`,
   replacing `5.15` with whatever kernel you want from `_data/kernels.json`. If this is
   your first time running these scripts, you will likely need to fetch the kernel first,
   which you can do with `make fetch-kernel KERNEL=5.15`.

2. Build your disk image (only needed if it's your first time, or you want to update the
   image). You can do this with `make build-images`.

3. Spin up the VM. You can do this with `make run KERNEL=5.15`. You can also omit the
   `KERNEL` argument if you just want to run the image's stock kernel.

4. Run your tests. SSH into the VM with `make ssh` and navigate to `/host`. This directory
   will contain all the files in this git repository where you can then run whatever
   tests you need (e.g. `make test` or `make e2e-test`).

5. When you're done, run `make stop` on the host to shut down the VM.

## Makefile Variables

- `KERNEL`: name of the kernel to use. Default is empty, implies no custom kernel.
- `KERNEL_URL`: git URL of the kernel to download when using `make add-kernel`.
- `IMAGE`: disk image to use from `_data/images`. Default is `kind.qcow2` (must be built with `make build-images`).
- `SSH_PORT`: port to forward for SSH. Default is 3333.
- `SSH_ARGS`: extra argument to pass to SSH. Default is empty.

## Makefile Targets

- `run`: spin up the VM.
- `start`: alias for `run`.
- `ssh`: SSH into the VM.
- `stop`: shut down the VM.
- `kill`: forcefully kill the VM. Prefer `stop` when possible.
- `install-lvh`: install lvh to the GOPATH.
- `fetch-kernel`: fetch `$KERNEL` from its git repo.
- `build-kernel`: configure and build `$KERNEL`.
- `add-kernel`: add `$KERNEL` with URL `$KERNEL_URL` to `_data/kernels.json`.
- `build-images`: build root filesystem images from `_data/images.json`.
