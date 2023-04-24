.PHONY: all clean
.SUFFIXES:

SHELL=/bin/bash # needed for the *.{o,ll,i,s} pattern in the clean target

CLANG  ?= clang
LLC    ?= llc

# Build the BPF programs for the detected architecture, default to x86, and
# allow easy overriding by using ?= for cross-compilation
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
	BPF_TARGET_ARCH ?= x86
endif
ifeq ($(UNAME_M),aarch64)
	BPF_TARGET_ARCH ?= arm64
endif
BPF_TARGET_ARCH ?= x86

OSSDIR := ../modules/tetragon-oss
OSSBPFDIR := $(OSSDIR)/bpf

TLSDIR := parsers/tls/
HTTPDIR := parsers/http/
NOPDIR := parsers/nop/
PARSERDIR = parsers/
ALIGNCHECKERDIR = alignchecker/
NETWORKINGDIR := networking/
ISOPROCESS := process/
FILEDIR := file/
PROCESSDIR := $(OSSBPFDIR)/process/
BPFTESTDIR := $(OSSBPFDIR)/test/

ALIGNCHECKER = bpf_alignchecker.o
PARSERS = bpf_sockops.o bpf_http.o bpf_http_verdict.o bpf_http_parser.o
TLS = bpf_tls_inet_send.o bpf_tls_skmsg.o bpf_tls_skskb_parser.o bpf_tls_skskb_verdict.o bpf_setsockopt.o
NOP = bpf_nop.o bpf_nop_verdict.o bpf_nop_parser.o
NETWORKING = bpf_tcpmon.o bpf_listen.o bpf_tcpclose.o bpf_tcpaccept.o bpf_tcp_send_check.o \
	     bpf_kfree_skb.o bpf_sock_release.o \
	     bpf_inet_send.o bpf_inet_send_lazy.o \
	     bpf_inet_send_lazy_kp.o bpf_udp_send_recv.o bpf_sock_create.o \
	     bpf_fd_lookup.o bpf_dev_queue_xmit.o \
	     bpf_tcp_rtt.o bpf_timestamp.o bpf_tcp_recv.o bpf_tcp_recv_lazy.o
PROCESS = bpf_execve_event.o bpf_execve_event_v53.o bpf_fork.o bpf_exit.o bpf_generic_kprobe.o \
	  bpf_generic_kprobe_v53.o bpf_generic_retkprobe.o bpf_generic_retkprobe_v53.o \
	  bpf_multi_kprobe_v53.o bpf_multi_retkprobe_v53.o \
	  bpf_generic_tracepoint.o bpf_generic_tracepoint_v53.o \
	  bpf_execve_event_v60.o bpf_generic_kprobe_v60.o bpf_generic_retkprobe_v60.o \
	  bpf_generic_tracepoint_v60.o \
	  bpf_multi_kprobe_v60.o bpf_multi_retkprobe_v60.o \
	  bpf_loader.o

FILE = bpf_filemap_fault.o  bpf_filemap_map_pages.o  bpf_filemap_page_mkwrite.o  bpf_finish_open.o  \
	  bpf_security_file_permission.o  bpf_vfs_unlink.o  bpf_vfs_fallocate.o bpf_vfs_open.o \
	  bpf_vfs_mkdir.o bpf_security_inode_rmdir.o bpf_security_path_rename.o bpf_vfs_rename.o bpf_vfs_rename_v419.o \
	  bpf_iterate_dir.o bpf_do_truncate.o bpf_chmod_common.o bpf_chown_common.o

BPFTEST = bpf_lseek.o bpf_globals.o

LDIR = ./lib
OSSIDIR = $(OSSBPFDIR)/include/
OSSLDIR = $(OSSBPFDIR)/lib
OSSLIBBPFDIR = $(OSSBPFDIR)/libbpf
OSSPDIR = $(OSSBPFDIR)/process

FLAGS := -I. \
	 -Wall -Werror \
	 -Wno-address-of-packed-member -Wno-compare-distinct-pointer-types -Wno-unknown-warning-option \
	 -O2

CLANG_FLAGS += $(FLAGS) -I $(OSSBPFDIR) -I $(OSSIDIR) -I $(LDIR) -I $(OSSLDIR) -I $(OSSPDIR) -I $(OSSLIBBPFDIR) -target bpf -emit-llvm -g -D__TARGET_ARCH_$(BPF_TARGET_ARCH) -fdebug-default-version=4
LLC_FLAGS   := -march=bpf -mcpu=v2 -mattr=dwarfris
LLC_FLAGS_ALU32 := -march=bpf -mcpu=v3 -mattr=dwarfris

OBJSDIR       := objs/
DEPSDIR       := deps/

PARSEROBJ     := $(addprefix $(OBJSDIR),$(PARSERS))
TLSOBJ        := $(addprefix $(OBJSDIR),$(TLS))
NOPOBJ        := $(addprefix $(OBJSDIR),$(NOP))
NETWORKINGOBJ := $(addprefix $(OBJSDIR),$(NETWORKING))
PROCESSOBJ    := $(addprefix $(OBJSDIR),$(PROCESS))
FILEOBJ       := $(addprefix $(OBJSDIR),$(FILE))
TESTOBJ       := $(addprefix $(OBJSDIR),$(BPFTEST))
ALIGNCHECKEROBJ := $(addprefix $(OBJSDIR),$(ALIGNCHECKER))
OBJS          := $(PARSEROBJ) $(TLSOBJ) $(NETWORKINGOBJ) $(PROCESSOBJ) $(FILEOBJ) $(TESTOBJ) $(NOPOBJ) $(ALIGNCHECKEROBJ)
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

deps/bpf_exit.d: $(ISOPROCESS)bpf_exit.c
	$(CLANG) $(CLANG_FLAGS) -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@)  $< > $@

# FILEDIR
objs/%.ll: $(FILEDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -c $< -o $@

objs/bpf_execve_event_v53.ll: $(PROCESSDIR)/bpf_execve_event.c
objs/bpf_generic_kprobe_v53.ll: $(PROCESSDIR)/bpf_generic_kprobe.c
objs/bpf_generic_retkprobe_v53.ll: $(PROCESSDIR)/bpf_generic_retkprobe.c
objs/bpf_multi_kprobe_v53.ll: $(PROCESSDIR)/bpf_generic_kprobe.c
objs/bpf_multi_retkprobe_v53.ll: $(PROCESSDIR)/bpf_generic_retkprobe.c
objs/bpf_generic_tracepoint_v53.ll: $(PROCESSDIR)/bpf_generic_tracepoint.c
objs/bpf_vfs_rename_v419.ll: $(FILEDIR)/bpf_vfs_rename.c

objs/bpf_multi_kprobe_v53.ll objs/bpf_multi_retkprobe_v53.ll:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -D__MULTI_KPROBE -c $< -o $@

objs/%_v419.ll:
	$(CLANG) $(CLANG_FLAGS) -c $< -o $@

objs/%_v53.ll:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -c $< -o $@

$(DEPSDIR)%.d: $(PROCESSDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@)   $< > $@

deps/bpf_execve_event_v53.d: $(PROCESSDIR)/bpf_execve_event.c
deps/bpf_generic_kprobe_v53.d: $(PROCESSDIR)/bpf_generic_kprobe.c
deps/bpf_generic_retkprobe_v53.d: $(PROCESSDIR)/bpf_generic_retkprobe.c
deps/bpf_multi_kprobe_v53.d: $(PROCESSDIR)/bpf_generic_kprobe.c
deps/bpf_multi_retkprobe_v53.d: $(PROCESSDIR)/bpf_generic_retkprobe.c
deps/bpf_generic_tracepoint_v53.d: $(PROCESSDIR)/bpf_generic_tracepoint.c
deps/bpf_vfs_rename_v419.d: $(FILEDIR)/bpf_vfs_rename.c

$(DEPSDIR)%_v419.d:
	$(CLANG) $(CLANG_FLAGS) -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@)   $< > $@

$(DEPSDIR)%_v53.d:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@)   $< > $@

objs/bpf_execve_event_v60.ll: $(PROCESSDIR)/bpf_execve_event.c
objs/bpf_generic_kprobe_v60.ll: $(PROCESSDIR)/bpf_generic_kprobe.c
objs/bpf_generic_retkprobe_v60.ll: $(PROCESSDIR)/bpf_generic_retkprobe.c
objs/bpf_multi_kprobe_v60.ll: $(PROCESSDIR)/bpf_generic_kprobe.c
objs/bpf_multi_retkprobe_v60.ll: $(PROCESSDIR)/bpf_generic_retkprobe.c
objs/bpf_generic_tracepoint_v60.ll: $(PROCESSDIR)/bpf_generic_tracepoint.c

objs/bpf_multi_kprobe_v60.ll objs/bpf_multi_retkprobe_v60.ll:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -D__V60_BPF_PROG -D__MULTI_KPROBE -c $< -o $@

objs/%_v60.ll:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -D__V60_BPF_PROG -c $< -o $@

deps/bpf_execve_event_v60.d: $(PROCESSDIR)/bpf_execve_event.c
deps/bpf_generic_kprobe_v60.d: $(PROCESSDIR)/bpf_generic_kprobe.c
deps/bpf_generic_retkprobe_v60.d: $(PROCESSDIR)/bpf_generic_retkprobe.c
deps/bpf_multi_kprobe_v60.d: $(PROCESSDIR)/bpf_generic_kprobe.c
deps/bpf_multi_retkprobe_v60.d: $(PROCESSDIR)/bpf_generic_retkprobe.c
deps/bpf_generic_tracepoint_v60.d: $(PROCESSDIR)/bpf_generic_tracepoint.c

$(DEPSDIR)%_v60.d:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG  -D__V60_BPF_PROG -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@)   $< > $@

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
