
GCC ?= gcc

PROGS = sigkill-tester capabilities-tester namespace-tester \
	dup-tester fork-tester nop dlopen \
	syscall-tester proctree

all: $(PROGS)
	make -C aio/
	make -C io_uring/
	make -C open/
	make -C read_write/
	make -C splice/
	make -C mmap/
	make -C net/

sigkill-tester: sigkill-tester.c
	$(GCC) -Wall -o sigkill-tester sigkill-tester.c

capabilities-tester: capabilities-tester.c
	$(GCC) -Wall $< -o $@ -lcap

namespace-tester: namespace-tester.c
	$(GCC) -Wall $< -o $@

dup-tester: dup-tester.c
	$(GCC) -Wall $< -o $@

fork-tester: fork-tester.c
	$(GCC) -Wall $< -o $@

nop: nop.c
	$(GCC) -Wall $< -o $@

dlopen: dlopen.c
	$(GCC) -Wall $< -o $@

syscall-tester: FORCE
	go build -o syscall-tester ./go/syscall-tester

proctree: proctree.c
	$(GCC) -Wall $< -o $@

.PHONY: clean
clean:
	make -C aio/ clean
	make -C io_uring/ clean
	make -C open/ clean
	make -C read_write/ clean
	make -C splice/ clean
	make -C mmap/ clean
	rm -f $(PROGS)

FORCE:
