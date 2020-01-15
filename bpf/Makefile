.PHONY: all copy

BPF = bpf_tcpmon.o bpf_tcpmonret.o bpf_bind.o bpf_execve.o bpf_execveat.o bpf_fork.o
FLAGS := -I. -Wall -Werror -Wno-unknown-warning-option -O2

CLANG_FLAGS += ${FLAGS} -target bpf -emit-llvm -Wno-address-of-packed-member -Wno-compare-distinct-pointer-types -g
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

bpf_tcpmonret.ll: bpf_tcpmonret.c $(LIB)
	@$(ECHO_CC)
	$(QUIET) ${CLANG} ${CLANG_FLAGS} -c $< -o $@

bpf_tcpmonret.o: bpf_tcpmonret.ll
	@$(ECHO_CC)
	$(QUIET) ${LLC} ${LLC_FLAGS} -filetype=obj -o $@ $(patsubst %.o,%.ll,$@)

bpf_bind.ll: bpf_bind.c $(LIB)
	@$(ECHO_CC)
	$(QUIET) ${CLANG} ${CLANG_FLAGS} -c $< -o $@

bpf_bind.o: bpf_bind.ll
	@$(ECHO_CC)
	$(QUIET) ${LLC} ${LLC_FLAGS} -filetype=obj -o $@ $(patsubst %.o,%.ll,$@)

bpf_execve.ll: bpf_execve.c $(LIB)
	@$(ECHO_CC)
	$(QUIET) ${CLANG} ${CLANG_FLAGS} -c $< -o $@

bpf_execve.o: bpf_execve.ll
	@$(ECHO_CC)
	$(QUIET) ${LLC} ${LLC_FLAGS} -filetype=obj -o $@ $(patsubst %.o,%.ll,$@)

bpf_execveat.ll: bpf_execveat.c $(LIB)
	@$(ECHO_CC)
	$(QUIET) ${CLANG} ${CLANG_FLAGS} -c $< -o $@

bpf_execveat.o: bpf_execveat.ll
	@$(ECHO_CC)
	$(QUIET) ${LLC} ${LLC_FLAGS} -filetype=obj -o $@ $(patsubst %.o,%.ll,$@)

bpf_fork.ll: bpf_fork.c $(LIB)
	@$(ECHO_CC)
	$(QUIET) ${CLANG} ${CLANG_FLAGS} -c $< -o $@

bpf_fork.o: bpf_fork.ll
	@$(ECHO_CC)
	$(QUIET) ${LLC} ${LLC_FLAGS} -filetype=obj -o $@ $(patsubst %.o,%.ll,$@)

clean:
	@$(ECHO_CLEAN)
	$(QUIET) $(foreach TARGET,$(SUBDIRS), \
		$(MAKE) -C $(TARGET) clean)
	$(QUIET)rm -fr *.o *.ll *.i *.s
	$(QUIET)rm -f $(TARGET)
