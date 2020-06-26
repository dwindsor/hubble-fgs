.PHONY: all

BPF = bpf_stream_connect.o bpf_tcpmon.o bpf_tcpmonret.o bpf_bind.o bpf_listen.o bpf_get_port.o \
      bpf_execve.o bpf_execve_event.o \
      bpf_sockops.o \
      bpf_fork.o

IDIR = ./include/
LIBBPF = ./libbpf/
LDIR = ./lib
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

FLAGS := -I. -I/usr/include/x86_64-linux-gnu/ \
	 -Wall -Werror \
	 -Wno-address-of-packed-member -Wno-compare-distinct-pointer-types -Wno-unknown-warning-option \
	 -O2
CLANG_FLAGS += ${FLAGS} -I ${LIBBPF} -I ${IDIR} -I ${LDIR} -target bpf -emit-llvm -g
LLC_FLAGS   := -march=bpf -mcpu=probe -mattr=dwarfris

CLANG  ?= clang
LLC    ?= llc

all: $(BPF)

$(BPF): %.o: %.c
	${CLANG} ${CLANG_FLAGS} -c $< -o - | ${LLC} ${LLC_FLAGS} -filetype=obj -o $@

clean:
	@$(ECHO_CLEAN)
	$(QUIET) $(foreach TARGET,$(SUBDIRS), \
		$(MAKE) -C $(TARGET) clean)
	$(QUIET)rm -fr *.o *.ll *.i *.s
	$(QUIET)rm -f $(TARGET)
