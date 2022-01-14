# KVM Workflow for CI and Local Dev

The scripts in contrib/kvm enable you to quickly and easily compile a new kernel and build
a root filesystem image for local FGS development and testing in KVM.

This workflow consists of the following basic components:

1. A script (contrib/kvm/build-image.sh) and Dockerfile to generate a new Ubuntu 20.04 image.
2. A script (contrib/kvm/build-kernel.sh) to compile a new version of the Linux kernel.
3. A script (contrib/kvm/run.sh) to spin up a new KVM virtual machine using the generated image and kernel.

## Limitations

In order to run FGS in KinD, the VM disk image needs to be at least 10GiB to fit all the
necessary Docker container images. Without KinD, the image can be as small as 4GiB.

## Configuring Your Environment

The values in `contrib/kvm/conf` should be sufficient to work on most Linux systems.
However, you can edit them as necessary:

- PUBKEY: The local path to a public key that should be copied into the VM image to enable ssh access.
- ROOTIMG: The path where the generated VM image should be stored.
- MNTDIR: Directory that should be used for mounting the root filesystem image.
- PACKAGES: A list of base packages that should be installed into the VM.
- VMDISK: Size of the VM disk in GB.
- VMRAM: Size of the VM's RAM in GB.
- VMCPUS: Number of CPUs to allocate to the VM.
- MACADDR: MAC address to use for the VM's NIC.
- SSHPORT: Port to forward on the local machine for ssh into the VM.
- KCONFIG: Path to the kernel config file that should be used when building the kernel
- KSRDIR: Path to clone kernel sources.
- KOUT: Directory to store compiled kernel artifacts.
- MODULESDIR: Directory to install kernel modules.

## Quick Start

1. Compile the latest bpf/bpf kernel:

        contrib/kvm/build-kernel.sh

2. Build the VM image:

        contrib/kvm/build-image.sh

3. Run the VM:

        contrib/kvm/run.sh

4. SSH into the VM:

        contrib/kvm/ssh.sh

## Building and Testing FGS

After SSHing into the VM, run `cd /fgs` to navigate to the path where the FGS project is
mounted via network share. To build FGS, you can run `make`. The correct version of libbpf
and clang were already installed when building the VM image. To test FGS, you can
similarly run `make test`. To run FGS locally, `./hubble-fgs --hubble-lib bpf/objs`.

## Running End-To-End Tests

TODO: This will be further automated in a follow-up patch.

1. Ensure that your VM image has at least 13GiB of space.
2. Create your k8s cluster with `kind create cluster`.
3. Install Cilium with `cilium install && cilium hubble enable`.
4. Build the FGS image with `make image`.
5. Register the image with KinD by running `kind load docker-image isovalent/hubble-fgs`.
6. Install FGS into your cluster as follows:

          helm repo add isovalent https://helm.isovalent.com
          helm repo update
          helm install hubble-enterprise isovalent/hubble-enterprise \
                 --version 9999.9999.9999-dev \
                 --set enterprise.image.repository=isovalent/hubble-fgs \
                 --set enterprise.image.tag=latest \
                 --set enterprise.exportAllowList="" \
                 --namespace kube-system

7. Deploy the demo application as follows:

          kubectl create namespace tenant-jobs
          kubectl -n tenant-jobs apply -f https://docs.isovalent.com/public/jobs-app-attack.yaml
          kubectl wait -n tenant-jobs --for=condition=Ready --all pod --timeout=30s

8. Allow events to generate:

          kubectl exec -n tenant-jobs deployment/jobposting -- curl localhost:9080 -m 1 || true
          sleep 60

9. Extract FGS logs:

          kubectl get pods --selector=app.kubernetes.io/name=hubble-enterprise \
              -n kube-system -o custom-columns=name:metadata.name --no-headers \
              | xargs -I{} kubectl cp -c enterprise -n kube-system {}:/var/run/cilium/hubble/fgs.log ./hubble-fgs-{}-fgs.log
          cat ./hubble-fgs*.log >> fgs.log

10. Run the event checker tests on `fgs.log`:

          go run ./tests/jobs.trace.go fgs.log
