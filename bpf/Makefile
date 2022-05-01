.PHONY: all clean
.SUFFIXES:

SHELL=/bin/bash # needed for the *.{o,ll,i,s} pattern in the clean target

OSSDIR := ../modules/tetragon-oss
OSSBPFDIR := $(OSSDIR)/bpf

TLSDIR := parsers/tls/
HTTPDIR := parsers/http/
NOPDIR := parsers/nop/
PARSERDIR = parsers/
ALIGNCHECKERDIR = alignchecker/
NETWORKINGDIR := networking/
ISOPROCESS := process/
PROCESSDIR := $(OSSBPFDIR)/process/
BPFTESTDIR := $(OSSBPFDIR)/test/

ALIGNCHECKER = bpf_alignchecker.o
PARSERS = bpf_sockops.o bpf_http.o bpf_http_verdict.o bpf_http_parser.o
TLS = bpf_tc_ingress.o bpf_tc_egress.o bpf_tls_skmsg.o bpf_tls_skskb_parser.o bpf_tls_skskb_verdict.o bpf_setsockopt.o
NOP = bpf_nop.o bpf_nop_verdict.o bpf_nop_parser.o
NETWORKING = bpf_tcpmon.o bpf_listen.o bpf_tcpclose.o bpf_tcp_send_check.o \
	     bpf_kfree_skb.o bpf_sock.o bpf_sock_release.o bpf_inet_send.o bpf_inet_send_lazy.o \
	     bpf_inet_send_lazy_kp.o bpf_udp_send_recv.o bpf_udp_send_recv_lazy.o bpf_sock_create.o \
	     bpf_fd_lookup.o bpf_dev_queue_xmit.o
PROCESS = bpf_execve_event.o bpf_execve_event_v53.o bpf_fork.o bpf_exit.o bpf_generic_kprobe.o \
	  bpf_generic_kprobe_v53.o bpf_generic_retkprobe.o bpf_generic_retkprobe_v53.o \
	  bpf_generic_tracepoint.o bpf_generic_tracepoint_v53.o bpf_file.o
BPFTEST = bpf_lseek.o bpf_globals.o

IDIR = ./include/
LIBBPF = ./libbpf/
LDIR = ./lib
OSSLDIR = $(OSSBPFDIR)/lib
OSSLIBBPFDIR = $(OSSBPFDIR)/libbpf
OSSPDIR = $(OSSBPFDIR)/process
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

FLAGS := -I. \
	 -Wall -Werror \
	 -Wno-address-of-packed-member -Wno-compare-distinct-pointer-types -Wno-unknown-warning-option \
	 -O2

CLANG_FLAGS += $(FLAGS) -I $(LIBBPF) -I $(IDIR) -I $(LDIR) -I $(OSSLDIR) -I $(OSSPDIR) -I $(OSSLIBBPFDIR) -target bpf -emit-llvm -g -D__TARGET_ARCH_$(ARCH)
LLC_FLAGS   := -march=bpf -mcpu=v2 -mattr=dwarfris
LLC_FLAGS_ALU32 := -march=bpf -mcpu=v3 -mattr=dwarfris

CLANG  ?= clang
LLC    ?= llc
ARCH   ?= x86

OBJSDIR       := objs/
DEPSDIR       := deps/

PARSEROBJ     := $(addprefix $(OBJSDIR),$(PARSERS))
TLSOBJ        := $(addprefix $(OBJSDIR),$(TLS))
NOPOBJ        := $(addprefix $(OBJSDIR),$(NOP))
NETWORKINGOBJ := $(addprefix $(OBJSDIR),$(NETWORKING))
PROCESSOBJ    := $(addprefix $(OBJSDIR),$(PROCESS))
TESTOBJ       := $(addprefix $(OBJSDIR),$(BPFTEST))
ALIGNCHECKEROBJ := $(addprefix $(OBJSDIR),$(ALIGNCHECKER))
OBJS          := $(PARSEROBJ) $(TLSOBJ) $(NETWORKINGOBJ) $(PROCESSOBJ) $(TESTOBJ) $(NOPOBJ) $(ALIGNCHECKEROBJ)
LLOBJS        := $(patsubst $(OBJSDIR)%.o,$(OBJSDIR)%.ll,$(OBJS))
DEPS          := $(patsubst $(OBJSDIR)%.ll,$(DEPSDIR)%.d,$(LLOBJS))

all: $(OBJS) $(DEPS)

# NB: https://www.gnu.org/software/make/manual/html_node/Prerequisite-Types.html
$(OBJS): | $(OBJSDIR)
$(DEPS): | $(DEPSDIR)
$(LLOBJS): | $(OBJSDIR)

$(OBJSDIR):
	mkdir $(OBJSDIR)

$(DEPSDIR):
	mkdir $(DEPSDIR)

# Generic build targets for each sub-dir

# ALIGNCHECKER
objs/%.ll: $(ALIGNCHECKERDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -c $< -o $@

$(DEPSDIR)%.d: $(ALIGNCHECKERDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@)   $< > $@

# PARSERDIR
objs/%.ll: $(PARSERDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -c $< -o $@

$(DEPSDIR)%.d: $(PARSERDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@)   $< > $@

# TLSDIR
objs/%.ll: $(TLSDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -I $(PARSERDIR) -c $< -o $@

$(DEPSDIR)%.d: $(TLSDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@)   $< > $@

# HTTPDIR
objs/%.ll: $(HTTPDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -I $(PARSERDIR) -c $< -o $@

$(DEPSDIR)%.d: $(HTTPDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@)   $< > $@

# NOPDIR
objs/%.ll: $(NOPDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -I $(NOPDIR) -c $< -o $@

$(DEPSDIR)%.d: $(NOPDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@)   $< > $@


# NETWORKINGDIR
objs/%.ll: $(NETWORKINGDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -c $< -o $@

$(DEPSDIR)%.d: $(NETWORKINGDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@)   $< > $@

# PROCESSDIR
objs/%.ll: $(PROCESSDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -c $< -o $@

# bpf_exit: special case because the enterprise version is different than OSS
objs/bpf_exit.ll: $(ISOPROCESS)bpf_exit.c
	$(CLANG) $(CLANG_FLAGS) -c $< -o $@

objs/bpf_file.ll: $(ISOPROCESS)bpf_file.c
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -c $< -o $@

objs/bpf_execve_event_v53.ll: $(PROCESSDIR)/bpf_execve_event.c
objs/bpf_generic_kprobe_v53.ll: $(PROCESSDIR)/bpf_generic_kprobe.c
objs/bpf_generic_retkprobe_v53.ll: $(PROCESSDIR)/bpf_generic_retkprobe.c
objs/bpf_generic_tracepoint_v53.ll: $(PROCESSDIR)/bpf_generic_tracepoint.c

objs/%_v53.ll:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -c $< -o $@

$(DEPSDIR)%.d: $(PROCESSDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@)   $< > $@

deps/bpf_execve_event_v53.d: $(PROCESSDIR)/bpf_execve_event.c
deps/bpf_generic_kprobe_v53.d: $(PROCESSDIR)/bpf_generic_kprobe.c
deps/bpf_generic_retkprobe_v53.d: $(PROCESSDIR)/bpf_generic_retkprobe.c
deps/bpf_generic_tracepoint_v53.d: $(PROCESSDIR)/bpf_generic_tracepoint.c

$(DEPSDIR)%_v53.d:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@)   $< > $@

# BPFTESTDIR
objs/%.ll: $(BPFTESTDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -c $< -o $@

$(DEPSDIR)%.d: $(BPFTESTDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@)   $< > $@

# Build sockops/sockmsg with ALU32 for 5.4+ kernels
objs/bpf_skskb_verdict.o: objs/bpf_skskb_verdict.ll
	$(LLC) $(LLC_FLAGS_ALU32) -filetype=obj $< -o $@

objs/bpf_skskb_parser.o: objs/bpf_skskb_parser.ll
	$(LLC) $(LLC_FLAGS_ALU32) -filetype=obj $< -o $@

objs/bpf_skmsg.o: objs/bpf_skmsg.ll
	$(LLC) $(LLC_FLAGS_ALU32) -filetype=obj $< -o $@

objs/bpf_http.o: objs/bpf_http.ll
	$(LLC) $(LLC_FLAGS_ALU32) -filetype=obj $< -o $@

objs/bpf_http_verdict.o: objs/bpf_http_verdict.ll
	$(LLC) $(LLC_FLAGS_ALU32) -filetype=obj $< -o $@

objs/bpf_http_parser.o: objs/bpf_http_parser.ll
	$(LLC) $(LLC_FLAGS_ALU32) -filetype=obj $< -o $@

# Remaining objects are built without mcpu=v2
objs/%.o: objs/%.ll
	$(LLC) $(LLC_FLAGS) -filetype=obj $< -o $@

# include dependencies
ifneq ($(MAKECMDGOALS),clean)
-include $(DEPS)
endif

clean:
	@$(ECHO_CLEAN)
	$(QUIET) $(foreach TARGET,$(SUBDIRS), \
		$(MAKE) -C $(TARGET) clean)
	$(QUIET)rm -f $(OBJSDIR)*.{o,ll,i,s}
	$(QUIET)rm -f $(DEPSDIR)*.d
