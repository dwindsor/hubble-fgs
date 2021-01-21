.PHONY: all clean
.SUFFIXES:

SHELL=/bin/bash # needed for the *.{o,ll,i,s} pattern in the clean target

TLSDIR := parsers/tls/
PARSERDIR = parsers/
NETWORKINGDIR := networking/
PROCESSDIR := process/
BPFTESTDIR := test/

PARSERS = bpf_sockops.o bpf_skmsg.o bpf_skskb_parser.o bpf_skskb_verdict.o 
TLS = bpf_skmsg_tls.o
TLSTC = bpf_tc_ingress.o bpf_tc_egress.o
NETWORKING = bpf_tcpmon.o bpf_tcpmonret.o bpf_listen.o bpf_tcpclose.o bpf_kfree_skb.o
PROCESS = bpf_execve_event.o bpf_fork.o bpf_exit.o bpf_cred.o bpf_generic_kprobe.o bpf_generic_retkprobe.o
BPFTEST = bpf_lseek.o

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
LLC_FLAGS_ALU32 := -march=bpf -mcpu=v3 -mattr=dwarfris

CLANG  ?= clang
LLC    ?= llc

OBJSDIR       := objs/

PARSEROBJ     := $(addprefix $(OBJSDIR),$(PARSERS))
TLSOBJ        := $(addprefix $(OBJSDIR),$(TLS))
TLSTCOBJ      := $(addprefix $(OBJSDIR),$(TLSTC))
NETWORKINGOBJ := $(addprefix $(OBJSDIR),$(NETWORKING))
PROCESSOBJ    := $(addprefix $(OBJSDIR),$(PROCESS))
TESTOBJ       := $(addprefix $(OBJSDIR),$(BPFTEST))
OBJS          := $(PARSEROBJ) $(TLSOBJ) ${TLSTCOBJ} $(NETWORKINGOBJ) $(PROCESSOBJ) $(TESTOBJ)

all: $(OBJS)

# NB: https://www.gnu.org/software/make/manual/html_node/Prerequisite-Types.html
$(OBJS): | $(OBJSDIR)

$(OBJSDIR):
	mkdir $(OBJSDIR)

objs/%.ll: $(PARSERDIR)%.c
	${CLANG} ${CLANG_FLAGS} -c $< -o $@

objs/%.ll: $(TLSDIR)%.c
	${CLANG} ${CLANG_FLAGS} -I ${PARSERDIR} -c $< -o $@

objs/%.ll: $(NETWORKINGDIR)%.c
	${CLANG} ${CLANG_FLAGS} -c $< -o $@

objs/%.ll: $(PROCESSDIR)%.c
	${CLANG} ${CLANG_FLAGS} -c $< -o $@

objs/%.ll: $(BPFTESTDIR)%.c
	${CLANG} ${CLANG_FLAGS} -c $< -o $@

# Build sockops/sockmsg with ALU32 for 5.4+ kernels
objs/bpf_skskb_verdict.o: objs/bpf_skskb_verdict.ll
	${LLC} ${LLC_FLAGS_ALU32} -filetype=obj $< -o $@

objs/bpf_skskb_parser.o: objs/bpf_skskb_parser.ll
	${LLC} ${LLC_FLAGS_ALU32} -filetype=obj $< -o $@

objs/bpf_skmsg.o: objs/bpf_skmsg.ll
	${LLC} ${LLC_FLAGS_ALU32} -filetype=obj $< -o $@

# Remaining objects are built without mcpu=v2
objs/%.o: objs/%.ll
	${LLC} ${LLC_FLAGS} -filetype=obj $< -o $@

clean:
	@$(ECHO_CLEAN)
	$(QUIET) $(foreach TARGET,$(SUBDIRS), \
		$(MAKE) -C $(TARGET) clean)
	$(QUIET)rm -f $(OBJSDIR)*.{o,ll,i,s}
