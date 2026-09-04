
GCC ?= gcc

PROGS = sigkill-tester capabilities-tester namespace-tester \
	dup-tester fork-tester nop dlopen \
	syscall-tester proctree memfd_exec

SUBDIRS = aio io_uring open read_write splice mmap net

all: $(PROGS)
	@for dir in $(SUBDIRS); do $(MAKE) -C $$dir || exit; done

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

memfd_exec: memfd_exec.c
	$(GCC) -Wall $< -o $@

.PHONY: clean
clean:
	@for dir in $(SUBDIRS); do $(MAKE) -C $$dir clean || exit; done
	rm -f $(PROGS)

.PHONY: all-files
all-files:
	@printf '%s\n' $(PROGS)
	@for dir in $(SUBDIRS); do \
		$(MAKE) -s -C $$dir all-files | sed "s|^|$$dir/|"; \
	done

FORCE:
