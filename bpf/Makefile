.PHONY: all clean
.SUFFIXES:

SHELL=/bin/bash # needed for the *.{o,ll,i,s} pattern in the clean target

TLSDIR := tls/
NETWORKINGDIR := networking/
PROCESSDIR := process/

TLS = bpf_sockops.o bpf_skmsg_tls.o bpf_cgrp_in_tls.o bpf_event_tls.o bpf_tc_ingress.o bpf_tc_egress.o
NETWORKING = bpf_stream_connect.o bpf_tcpmon.o bpf_tcpmonret.o bpf_bind.o bpf_listen.o bpf_get_port.o
PROCESS = bpf_execve_event.o bpf_fork.o

IDIR = ./include/
LIBBPF = ./libbpf/
LDIR = ./lib
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

FLAGS := -I. -I/usr/include/x86_64-linux-gnu/ \
	 -Wall -Werror \
	 -Wno-address-of-packed-member -Wno-compare-distinct-pointer-types -Wno-unknown-warning-option \
	 -O2

CLANG_FLAGS += ${FLAGS} -I ${LIBBPF} -I ${IDIR} -I ${LDIR} -target bpf -emit-llvm -g
LLC_FLAGS   := -march=bpf -mcpu=v2 -mattr=dwarfris


CLANG  ?= clang
LLC    ?= llc

OBJSDIR       := objs/

TLSOBJ        := $(addprefix $(OBJSDIR),$(TLS))
NETWORKINGOBJ := $(addprefix $(OBJSDIR),$(NETWORKING))
PROCESSOBJ    := $(addprefix $(OBJSDIR),$(PROCESS))
OBJS          := $(TLSOBJ) $(NETWORKINGOBJ) $(PROCESSOBJ)

all: $(OBJS)

# NB: https://www.gnu.org/software/make/manual/html_node/Prerequisite-Types.html
$(OBJS): | $(OBJSDIR)

$(OBJSDIR):
	mkdir $(OBJSDIR)

objs/%.ll: $(TLSDIR)%.c
	${CLANG} ${CLANG_FLAGS} -c $< -o $@

objs/%.ll: $(NETWORKINGDIR)%.c
	${CLANG} ${CLANG_FLAGS} -c $< -o $@

objs/%.ll: $(PROCESSDIR)%.c
	${CLANG} ${CLANG_FLAGS} -c $< -o $@

objs/%.o: objs/%.ll
	${LLC} ${LLC_FLAGS} -filetype=obj $< -o $@

clean:
	@$(ECHO_CLEAN)
	$(QUIET) $(foreach TARGET,$(SUBDIRS), \
		$(MAKE) -C $(TARGET) clean)
	$(QUIET)rm -f $(OBJSDIR)*.{o,ll,i,s}
