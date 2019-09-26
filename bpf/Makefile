.PHONY: all copy

BPF = bpf_tcpmon.o bpf_execve.o
FLAGS := -I. -Wall -Werror -Wno-unknown-warning-option -O2

CLANG_FLAGS += ${FLAGS} -target bpf -emit-llvm -Wno-address-of-packed-member -Wno-compare-distinct-pointer-types
LLC_FLAGS   := -march=bpf -mcpu=probe -mattr=dwarfris

CLANG  ?= clang
LLC    ?= llc

all: $(BPF)

UNAME_R := $(shell uname -r)

copy:
	cp ./include/$(UNAME_R)/vmlinux.h ./

bpf_tcpmon.ll: bpf_tcpmon.c $(LIB)
	@$(ECHO_CC)
	$(QUIET) ${CLANG} ${CLANG_FLAGS} -c $< -o $@

bpf_tcpmon.o: bpf_tcpmon.ll
	@$(ECHO_CC)
	$(QUIET) ${LLC} ${LLC_FLAGS} -filetype=obj -o $@ $(patsubst %.o,%.ll,$@)

bpf_execve.ll: bpf_execve.c $(LIB)
	@$(ECHO_CC)
	$(QUIET) ${CLANG} ${CLANG_FLAGS} -c $< -o $@

bpf_execve.o: bpf_execve.ll
	@$(ECHO_CC)
	$(QUIET) ${LLC} ${LLC_FLAGS} -filetype=obj -o $@ $(patsubst %.o,%.ll,$@)

clean:
	@$(ECHO_CLEAN)
	$(QUIET) $(foreach TARGET,$(SUBDIRS), \
		$(MAKE) -C $(TARGET) clean)
	$(QUIET)rm -fr *.o *.ll *.i *.s
	$(QUIET)rm -f $(TARGET)
