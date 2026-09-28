KERNEL     ?=
KERNEL_URL ?=
# renovate: datasource=docker
IMAGE      ?= quay.io/lvh-images/kind:6.1-20260928.013030@sha256:f07910758d227fdcbed36563d7b8e421b83e43bd15c27a509fe0b14092a0d613
SSH_PORT   ?= 3333
SSH_ARGS   ?=
HOST_MOUNT ?= ../..
MEMORY     ?= 4G
CPU        ?= 2
FG         ?=

ifeq ($(KERNEL),)
__kernel_flags =
else
__kernel_flags = --kernel _data/kernels/${KERNEL}/tar-install/boot/vmlinuz*
endif

ifeq ($(FG),)
__daemonize_flags = --daemonize
else
__daemonize_flags =
endif

.PHONY: help
help:
	@echo 'contrib/kvm: Use little-vm-helper to create/manage/run KVM virtual machines for Tetragon Enterprise development.'
	@echo ''
	@echo 'This Makefile contains targets that wrap lvh and make it easier to create and manage your virtual machines.'
	@echo 'Refer to the help below for a list of variables and targets.'
	@echo ''
	@echo 'Variables:'
	@echo '    KERNEL     - kernel name to fetch, add, or build, according to kernels.json'
	@echo '    KERNEL_URL - URL of the kernel to fetch'
	@echo '    IMAGE      - name of root filesystem image (default is "kind.qcow2")'
	@echo '    SSH_PORT   - ssh port for the VM (default is "3333")'
	@echo '    SSH_ARGS   - extra arguments for ssh'
	@echo '    HOST_MOUNT - directory to mount under /host in the VM default is "../..")'
	@echo '    MEMORY     - memory for the VM (default is "4G")'
	@echo '    CPU        - CPU count for the VM (default is "2")'
	@echo '    FG         - set to non-empty value to run VM in the foreground'
	@echo ''
	@echo 'Targets:'
	@echo '    install-lvh  - install the lvh CLI'
	@echo '    run          - start the VM. Configure with KERNEL, IMAGE, SSH_PORT, HOST_MOUNT, MEMORY, and CPU'
	@echo '    start        - alias for start'
	@echo '    ssh          - ssh into the VM. Configure with SSH_PORT and SSH_ARGS'
	@echo '    stop         - attempt to stop the VM gracefully'
	@echo '    kill         - kill the VM'
	@echo '    fetch-kernel - fetch a kernel. Configure with KERNEL'
	@echo '    build-kernel - build a kernel. Configure with KERNEL'
	@echo '    add-kernel   - add a new kernel. Configure with KERNEL and KERNEL_URL'

.PHONY: run
run:
	sudo lvh run --image ${IMAGE} -p ${SSH_PORT}:22 ${__daemonize_flags} --host-mount ${HOST_MOUNT} ${__kernel_flags} --mem ${MEMORY} --cpu ${CPU}

.PHONY: start
start: run

.PHONY: ssh
ssh:
	@test ${SSH_PORT}
	ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -p ${SSH_PORT} root@localhost ${SSH_ARGS}

.PHONY: stop
stop:
	@echo "Attempting to gracefully shut down VM..."
	${MAKE} ssh SSHARGS="shutdown now -P"

.PHONY: kill
kill:
	@echo "Forcefully shutting down QEMU process..."
	sudo kill $(shell pgrep "qemu-system" | head -n 1)

.PHONY: install-lvh
install-lvh:
	go install github.com/cilium/little-vm-helper/cmd/lvh@latest

.PHONY: fetch-kernel
fetch-kernel:
	@test ${KERNEL}
	lvh kernels fetch --dir _data ${KERNEL}

.PHONY: build-kernel
build-kernel:
	@test ${KERNEL}
	lvh kernels configure --dir _data ${KERNEL}
	lvh kernels build --dir _data ${KERNEL}

.PHONY: add-kernel
add-kernel:
	@test ${KERNEL}
	@test ${KERNEL_URL}
	lvh kernels --dir _data add ${KERNEL} ${KERNEL_URL} --fetch
