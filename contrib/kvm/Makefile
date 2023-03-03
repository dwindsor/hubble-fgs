KERNEL     ?=
KERNEL_URL ?=
IMAGE      ?= kind.qcow2
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

.PHONY: run
run:
	sudo lvh run --image _data/images/${IMAGE} -p ${SSH_PORT}:22 ${__daemonize_flags} --host-mount ${HOST_MOUNT} ${__kernel_flags} --mem ${MEMORY} --cpu ${CPU}

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

.PHONY: build-images
build-images:
	./helpers/build-image.sh
