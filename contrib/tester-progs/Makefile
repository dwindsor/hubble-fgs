
GCC ?= gcc

PROGS = sigkill-tester capabilities-tester namespace-tester dup-tester fork-tester

all: $(PROGS)
	make -C aio/
	make -C io_uring/
	make -C open/
	make -C read_write/
	make -C splice/
	make -C mmap/

sigkill-tester: sigkill-tester.c
	$(GCC) -Wall -o sigkill-tester sigkill-tester.c

capabilities-tester: capabilities-tester.c
	$(GCC) -Wall $< -o $@ -static -lcap

namespace-tester: namespace-tester.c
	$(GCC) -Wall $< -o $@ -static

dup-tester: dup-tester.c
	$(GCC) -Wall $< -o $@ -static

fork-tester: fork-tester.c
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
