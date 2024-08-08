include ../Makefile.defs

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

OSSBPFDIR := $(OSS_DIR)/bpf

TLSDIR := parsers/tls/
HTTPDIR := parsers/http/
NOPDIR := parsers/nop/
PARSERDIR = parsers/
ALIGNCHECKERDIR = alignchecker/
ALIGNCHECKEROSSDIR = $(OSSBPFDIR)/alignchecker/
NETWORKINGDIR := networking/
SOCKTRACKDIR := networking/socktrack/
L2DIR  := networking/l2/
L3DIR  := networking/l3/
TCPDIR := networking/l3/tcp/
ICMPDIR := networking/l3/icmp/
PINGDIR := networking/l3/ping/
UDPDIR  := networking/l3/udp/
RAWSOCKDIR := networking/rawsock/
TIMESTAMPDIR := networking/timestamp/
ISOPROCESS := process/
FILEDIR := file/
PROCESSDIR := $(OSSBPFDIR)/process/
BPFTESTDIR := $(OSSBPFDIR)/test/

ALIGNCHECKER = bpf_alignchecker.o
ALIGNCHECKEROSS = bpf_alignchecker_oss.o
PARSERS = bpf_sockops.o bpf_http.o bpf_http_verdict.o bpf_http_parser.o
TLS = bpf_tls_inet_send.o bpf_tls_skmsg.o bpf_tls_skskb_parser.o bpf_tls_skskb_verdict.o bpf_setsockopt.o
NOP = bpf_nop.o bpf_nop_verdict.o bpf_nop_parser.o

NETWORKING = bpf_kfree_skb.o bpf_fd_lookup.o

SOCKTRACK = bpf_sk_alloc.o bpf_security_sk_alloc.o

UDP = bpf_udp_bind.o bpf_udp_bind_5_15.o bpf_udp_bind_dummy.o \
      bpf_udp_inet_lazy_kp.o \
      bpf_udp_send_recv.o

TCP = bpf_tcp_accept.o bpf_tcp_close_and_accept.o \
      bpf_tcp_connect.o bpf_tcp_connect_5_15.o    \
      bpf_tcp_listen.o \
      bpf_tcp_rtt.o \
      bpf_tcp_send_check.o

L2 = bpf_dev_queue_xmit.o

ICMP = bpf_icmp_rcv.o
PING = bpf_pingsock_create.o
L3 = bpf_cgroup_net_load_5-4.o bpf_cgroup_net_load.o bpf_cgroup_net.o

RAWSOCK = bpf_rawsock_create.o

TIMESTAMP =  bpf_timestamp.o

PROCESS = bpf_execve_event.o bpf_execve_event_v53.o bpf_fork.o bpf_exit.o bpf_generic_kprobe.o \
	  bpf_execve_bprm_commit_creds.o \
	  bpf_generic_kprobe_v53.o bpf_generic_retkprobe.o bpf_generic_retkprobe_v53.o \
	  bpf_multi_kprobe_v53.o bpf_multi_retkprobe_v53.o \
	  bpf_generic_tracepoint.o bpf_generic_tracepoint_v53.o \
	  bpf_generic_uprobe.o bpf_generic_uprobe_v53.o bpf_generic_uprobe_v511.o bpf_generic_uprobe_v61.o \
	  bpf_execve_event_v61.o bpf_generic_kprobe_v61.o bpf_generic_retkprobe_v61.o \
	  bpf_generic_tracepoint_v61.o \
	  bpf_multi_kprobe_v61.o bpf_multi_retkprobe_v61.o \
	  bpf_multi_kprobe_v61.o bpf_multi_retkprobe_v61.o \
	  bpf_execve_event_v511.o \
	  bpf_generic_kprobe_v511.o bpf_generic_retkprobe_v511.o \
	  bpf_generic_tracepoint_v511.o \
	  bpf_multi_kprobe_v511.o bpf_multi_retkprobe_v511.o \
	  bpf_loader.o \
	  bpf_enforcer.o bpf_multi_enforcer.o bpf_fmodret_enforcer.o \
	  bpf_cgroup.o

FILE = bpf_filemap_fault.o bpf_filemap_fault_v419.o bpf_filemap_map_pages.o bpf_filemap_map_pages_v419.o bpf_filemap_page_mkwrite.o bpf_filemap_page_mkwrite_v419.o bpf_finish_open.o bpf_finish_open_v419.o \
	  bpf_security_file_permission.o bpf_security_file_permission_v419.o bpf_vfs_unlink.o bpf_vfs_unlink_v419.o bpf_vfs_fallocate.o bpf_vfs_fallocate_v419.o bpf_vfs_open.o bpf_vfs_open_v419.o \
	  bpf_vfs_mkdir.o bpf_vfs_mkdir_v419.o bpf_security_inode_rmdir.o bpf_security_inode_rmdir_v419.o bpf_security_path_rename.o bpf_security_path_rename_v419.o bpf_vfs_rename.o bpf_vfs_rename_v419.o \
	  bpf_iterate_dir.o bpf_iterate_dir_v419.o bpf_security_inode_setattr.o bpf_security_inode_setattr_v419.o \
	  bpf_security_mmap_file_lsm.o bpf_security_mmap_file_fmod.o \
	  bpf_security_inode_create_lsm.o bpf_security_inode_create_fmod.o \
	  bpf_iterate_dir_enforce_lsm.o bpf_iterate_dir_enforce_fmod.o \
	  bpf_security_file_permission_enforce_lsm.o bpf_security_file_permission_enforce_fmod.o \
	  bpf_security_inode_rmdir_enforce_lsm.o bpf_security_inode_rmdir_enforce_fmod.o \
	  bpf_vfs_mkdir_enforce_lsm.o bpf_vfs_mkdir_enforce_fmod.o \
	  bpf_vfs_unlink_enforce_lsm.o bpf_vfs_unlink_enforce_fmod.o \
	  bpf_vfs_rename_enforce_lsm.o bpf_vfs_rename_enforce_fmod.o \
	  bpf_security_inode_setattr_enforce_lsm.o bpf_security_inode_setattr_enforce_fmod.o \
	  bpf_security_inode_setattr_enforce_fmod_v60.o bpf_security_inode_setattr_enforce_fmod_v63.o \
	  bpf_security_bprm_check.o bpf_security_bprm_check_v419.o bpf_security_bprm_check_enforce_lsm.o bpf_security_bprm_check_enforce_fmod.o \
	  bpf_security_bprm_check_enforce_lsm_digest.o bpf_file_exec.o bpf_io_uring.o bpf_fsnotify.o bpf_fsnotify_v419.o bpf_lsm_check.o \
	  bpf_security_inode_link.o bpf_security_inode_link_v419.o bpf_security_inode_link_enforce_lsm.o bpf_security_inode_link_enforce_fmod.o \
	  bpf_security_file_open.o bpf_security_file_open_v419.o bpf_security_file_open_enforce_lsm.o bpf_security_file_open_enforce_fmod.o \
	  fmod_security_file_permission.o lsm_security_kernel_read_file.o lsm_security_file_open.o lsm_security_mmap_file.o lsm_security_path_link.o \
	  lsm_security_path_mkdir.o lsm_security_path_rmdir.o lsm_security_path_unlink.o lsm_security_bprm_check.o lsm_security_path_setattr.o lsm_security_path_rename.o \
	  probe_security_file_permission.o probe_security_path_truncate.o probe_security_file_open.o probe_security_kernel_read_file.o probe_bpf_loop.o probe_for_each_map_elem.o lsm_test_glob.o


BPFTEST = bpf_lseek.o

LDIR = ./lib
OSSIDIR = $(OSSBPFDIR)/include/
OSSLDIR = $(OSSBPFDIR)/lib
OSSLIBBPFDIR = $(OSSBPFDIR)/libbpf
OSSPDIR = $(OSSBPFDIR)/process

FLAGS := -I. \
	 -Wall -Werror \
	 -Wno-address-of-packed-member -Wno-compare-distinct-pointer-types -Wno-unknown-warning-option \
	 -O2

DEBUG ?= 0
ifeq ($(DEBUG),1)
	__DEBUG_FLAGS = -DTETRAGON_BPF_DEBUG
endif

NETINC += -I $(NETWORKINGDIR) -I $(TCPDIR) -I $(UDPDIR) -I $(TIMESTAMP)
CLANG_FLAGS += $(FLAGS) -I $(OSSBPFDIR) -I $(OSSIDIR) -I $(LDIR) -I $(OSSLDIR) -I $(OSSPDIR) -I $(OSSLIBBPFDIR) $(NETINC) -target bpf -emit-llvm -g -D__TARGET_ARCH_$(BPF_TARGET_ARCH) -fdebug-default-version=4 $(__DEBUG_FLAGS)
LLC_FLAGS   := -march=bpf -mcpu=v2 -mattr=dwarfris
LLC_FLAGS_ALU32 := -march=bpf -mcpu=v3 -mattr=dwarfris

OBJSDIR       := objs/
DEPSDIR       := deps/

PARSEROBJ     := $(addprefix $(OBJSDIR),$(PARSERS))
TLSOBJ        := $(addprefix $(OBJSDIR),$(TLS))
NOPOBJ        := $(addprefix $(OBJSDIR),$(NOP))
NETWORKINGOBJ := $(addprefix $(OBJSDIR),$(NETWORKING))
SOCKTRACKOBJ  := $(addprefix $(OBJSDIR),$(SOCKTRACK))
UDPOBJ	      := $(addprefix $(OBJSDIR),$(UDP))
TCPOBJ        := $(addprefix $(OBJSDIR),$(TCP))
L2OBJ	      := $(addprefix $(OBJSDIR),$(L2))
L3OBJ	      := $(addprefix $(OBJSDIR),$(L3))
PINGOBJ	      := $(addprefix $(OBJSDIR),$(PING))
ICMPOBJ	      := $(addprefix $(OBJSDIR),$(ICMP))
RAWSOCKOBJ    := $(addprefix $(OBJSDIR),$(RAWSOCK))
TIMESTAMPOBJ  := $(addprefix $(OBJSDIR),$(TIMESTAMP))
PROCESSOBJ    := $(addprefix $(OBJSDIR),$(PROCESS))
FILEOBJ       := $(addprefix $(OBJSDIR),$(FILE))
TESTOBJ       := $(addprefix $(OBJSDIR),$(BPFTEST))
ALIGNCHECKEROBJ := $(addprefix $(OBJSDIR),$(ALIGNCHECKER))
ALIGNCHECKEROSSOBJ := $(addprefix $(OBJSDIR),$(ALIGNCHECKEROSS))
OBJS          := $(PARSEROBJ) $(TLSOBJ) $(NETWORKINGOBJ) $(SOCKTRACKOBJ) $(UDPOBJ) $(TCPOBJ) $(L2OBJ) $(L3OBJ) $(PINGOBJ) $(ICMPOBJ) $(RAWSOCKOBJ) $(TIMESTAMPOBJ) $(PROCESSOBJ) $(FILEOBJ) $(TESTOBJ) $(NOPOBJ) $(ALIGNCHECKEROBJ) $(ALIGNCHECKEROSSOBJ)
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

# ALIGNCHECKER
objs/%_oss.ll: $(ALIGNCHECKEROSSDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -c $< -o $@

$(DEPSDIR)%_oss.d: $(ALIGNCHECKEROSSDIR)%.c
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

# SOCKTRACKDIR
objs/%.ll: $(SOCKTRACKDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -c $< -o $@

$(DEPSDIR)%.d: $(SOCKTRACKDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@)   $< > $@

# UDPDIR
objs/%.ll: $(UDPDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -c $< -o $@

$(DEPSDIR)%.d: $(UDPDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@)   $< > $@

# TCPDIR
objs/%.ll: $(TCPDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -c $< -o $@

$(DEPSDIR)%.d: $(TCPDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@)   $< > $@

# L2DIR
objs/%.ll: $(L2DIR)%.c
	$(CLANG) $(CLANG_FLAGS) -c $< -o $@

$(DEPSDIR)%.d: $(L2DIR)%.c
	$(CLANG) $(CLANG_FLAGS) -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@)   $< > $@

# L3DIR
objs/%.ll: $(L3DIR)%.c
	$(CLANG) $(CLANG_FLAGS) -c $< -o $@

$(DEPSDIR)%.d: $(L3DIR)%.c
	$(CLANG) $(CLANG_FLAGS) -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@)   $< > $@

#PING
objs/%.ll: $(PINGDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -c $< -o $@

$(DEPSDIR)%.d: $(PINGDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@)   $< > $@

#ICMP
objs/%.ll: $(ICMPDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -c $< -o $@

$(DEPSDIR)%.d: $(ICMPDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@)   $< > $@

# RAWSOCKDIR
objs/%.ll: $(RAWSOCKDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -c $< -o $@

$(DEPSDIR)%.d: $(RAWSOCKDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@)   $< > $@

# TIMESTAMPDIR
objs/%.ll: $(TIMESTAMPDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -c $< -o $@

$(DEPSDIR)%.d: $(TIMESTAMPDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@)   $< > $@

# PROCESSDIR
objs/%.ll: $(PROCESSDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -c $< -o $@

# bpf_exit: special case because the enterprise version is different than OSS
objs/bpf_exit.ll: $(ISOPROCESS)bpf_exit.c
	$(CLANG) $(CLANG_FLAGS) -c $< -o $@

deps/bpf_exit.d: $(ISOPROCESS)bpf_exit.c
	$(CLANG) $(CLANG_FLAGS) -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@)  $< > $@

# bpf_ee_execve_event: special case because the enterprise version is different than OSS
objs/bpf_execve_event.ll: $(ISOPROCESS)bpf_ee_execve_event.c
	$(CLANG) $(CLANG_FLAGS) -c $< -o $@

deps/bpf_execve_event.d: $(ISOPROCESS)bpf_ee_execve_event.c
	$(CLANG) $(CLANG_FLAGS) -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@)  $< > $@

## bpf_enforcer: __BPF_OVERRIDE_RETURN, but no __MULTI_KPROBE
objs/bpf_enforcer.ll: $(PROCESSDIR)/bpf_enforcer.c
	$(CLANG) $(CLANG_FLAGS) -D__BPF_OVERRIDE_RETURN -c $< -o $@

$(DEPSDIR)bpf_enforcer.d: $(PROCESSDIR)/bpf_enforcer.c
	$(CLANG) $(CLANG_FLAGS) -D__BPF_OVERRIDE_RETURN -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@) $< > $@

## bpf_multi_enforcer: __BPF_OVERRIDE_RETURN and __MULTI_KPROBE
objs/bpf_multi_enforcer.ll: $(PROCESSDIR)/bpf_enforcer.c
	$(CLANG) $(CLANG_FLAGS) -D__BPF_OVERRIDE_RETURN -D__MULTI_KPROBE -c $< -o $@

$(DEPSDIR)/bpf_multi_enforcer.d: $(PROCESSDIR)/bpf_enforcer.c
	$(CLANG) $(CLANG_FLAGS) -D__BPF_OVERRIDE_RETURN -D__MULTI_KPROBE -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@) $< > $@

## bpf_fmodret_enforcer no bpf_override_return: we need fmod_ret
objs/bpf_fmodret_enforcer.ll: $(PROCESSDIR)/bpf_enforcer.c
	$(CLANG) $(CLANG_FLAGS) -c $< -o $@

$(DEPSDIR)/bpf_fmodret_enforcer.d: $(PROCESSDIR)/bpf_enforcer.c
	$(CLANG) $(CLANG_FLAGS) -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@) $< > $@

# FILEDIR
objs/%.ll: $(FILEDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -c $< -o $@

objs/%_lsm.ll:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -D__FILE_ENFORCE_LSM -c $< -o $@

$(DEPSDIR)%_lsm.d:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -D__FILE_ENFORCE_LSM -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@)   $< > $@

objs/%_lsm_digest.ll:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -D__FILE_ENFORCE_LSM -D__FILE_DIGEST_LSM -c $< -o $@

$(DEPSDIR)%_lsm_digest.d:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -D__FILE_ENFORCE_LSM -D__FILE_DIGEST_LSM -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@)   $< > $@

objs/%_fmod.ll:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -D__FILE_ENFORCE_FMOD -c $< -o $@

$(DEPSDIR)%_fmod.d:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -D__FILE_ENFORCE_FMOD -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@)   $< > $@

objs/%_lsm_v60.ll:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -D__FILE_ENFORCE_LSM -D__V60_BPF_PROG -c $< -o $@

$(DEPSDIR)%_lsm_v60.d:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -D__FILE_ENFORCE_LSM -D__V60_BPF_PROG -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@)   $< > $@

objs/%_fmod_v60.ll:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -D__FILE_ENFORCE_FMOD -D__V60_BPF_PROG -c $< -o $@

$(DEPSDIR)%_fmod_v60.d:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -D__FILE_ENFORCE_FMOD -D__V60_BPF_PROG -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@)   $< > $@

objs/%_lsm_v63.ll:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -D__FILE_ENFORCE_LSM -D__V63_BPF_PROG -c $< -o $@

$(DEPSDIR)%_lsm_v63.d:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -D__FILE_ENFORCE_LSM -D__V63_BPF_PROG -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@)   $< > $@

objs/%_fmod_v63.ll:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -D__FILE_ENFORCE_FMOD -D__V63_BPF_PROG -c $< -o $@

$(DEPSDIR)%_fmod_v63.d:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -D__FILE_ENFORCE_FMOD -D__V63_BPF_PROG -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@)   $< > $@

objs/bpf_execve_event_v53.ll: $(ISOPROCESS)/bpf_ee_execve_event.c
objs/bpf_generic_kprobe_v53.ll: $(PROCESSDIR)/bpf_generic_kprobe.c
objs/bpf_generic_retkprobe_v53.ll: $(PROCESSDIR)/bpf_generic_retkprobe.c
objs/bpf_multi_kprobe_v53.ll: $(PROCESSDIR)/bpf_generic_kprobe.c
objs/bpf_multi_retkprobe_v53.ll: $(PROCESSDIR)/bpf_generic_retkprobe.c
objs/bpf_generic_uprobe_v53.ll: $(PROCESSDIR)/bpf_generic_uprobe.c
objs/bpf_generic_tracepoint_v53.ll: $(PROCESSDIR)/bpf_generic_tracepoint.c
objs/bpf_vfs_rename_v419.ll: $(FILEDIR)/bpf_vfs_rename.c
objs/bpf_filemap_fault_v419.ll: $(FILEDIR)/bpf_filemap_fault.c
objs/bpf_filemap_map_pages_v419.ll: $(FILEDIR)/bpf_filemap_map_pages.c
objs/bpf_filemap_page_mkwrite_v419.ll: $(FILEDIR)/bpf_filemap_page_mkwrite.c
objs/bpf_security_file_permission_v419.ll: $(FILEDIR)/bpf_security_file_permission.c
objs/bpf_vfs_unlink_v419.ll: $(FILEDIR)/bpf_vfs_unlink.c
objs/bpf_security_inode_setattr_v419.ll: $(FILEDIR)/bpf_security_inode_setattr.c
objs/bpf_vfs_fallocate_v419.ll: $(FILEDIR)/bpf_vfs_fallocate.c
objs/bpf_finish_open_v419.ll: $(FILEDIR)/bpf_finish_open.c
objs/bpf_vfs_open_v419.ll: $(FILEDIR)/bpf_vfs_open.c
objs/bpf_fsnotify_v419.ll: $(FILEDIR)/bpf_fsnotify.c
objs/bpf_security_inode_rmdir_v419.ll: $(FILEDIR)/bpf_security_inode_rmdir.c
objs/bpf_vfs_mkdir_v419.ll: $(FILEDIR)/bpf_vfs_mkdir.c
objs/bpf_iterate_dir_v419.ll: $(FILEDIR)/bpf_iterate_dir.c
objs/bpf_security_bprm_check_v419.ll: $(FILEDIR)/bpf_security_bprm_check.c
objs/bpf_security_path_rename_v419.ll: $(FILEDIR)/bpf_security_path_rename.c
objs/bpf_security_inode_link_v419.ll: $(FILEDIR)/bpf_security_inode_link.c
objs/bpf_security_file_open_v419.ll: $(FILEDIR)/bpf_security_file_open.c

objs/bpf_multi_kprobe_v53.ll objs/bpf_multi_retkprobe_v53.ll:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -D__MULTI_KPROBE -c $< -o $@

objs/%_v419.ll:
	$(CLANG) $(CLANG_FLAGS) -c $< -o $@

objs/%_v53.ll:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -c $< -o $@

$(DEPSDIR)%.d: $(PROCESSDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@)   $< > $@

deps/bpf_execve_event_v511.d: $(ISOPROCESS)/bpf_ee_execve_event.c
deps/bpf_generic_kprobe_v511.d: $(PROCESSDIR)/bpf_generic_kprobe.c
deps/bpf_generic_retkprobe_v511.d: $(PROCESSDIR)/bpf_generic_retkprobe.c
deps/bpf_multi_kprobe_v511.d: $(PROCESSDIR)/bpf_generic_kprobe.c
deps/bpf_multi_retkprobe_v511.d: $(PROCESSDIR)/bpf_generic_retkprobe.c
deps/bpf_generic_uprobe_v511.d: $(PROCESSDIR)/bpf_generic_uprobe.c
deps/bpf_generic_tracepoint_v511.d: $(PROCESSDIR)/bpf_generic_tracepoint.c
deps/bpf_execve_event_v53.d: $(ISOPROCESS)/bpf_ee_execve_event.c
deps/bpf_generic_kprobe_v53.d: $(PROCESSDIR)/bpf_generic_kprobe.c
deps/bpf_generic_retkprobe_v53.d: $(PROCESSDIR)/bpf_generic_retkprobe.c
deps/bpf_multi_kprobe_v53.d: $(PROCESSDIR)/bpf_generic_kprobe.c
deps/bpf_multi_retkprobe_v53.d: $(PROCESSDIR)/bpf_generic_retkprobe.c
deps/bpf_generic_uprobe_v53.d: $(PROCESSDIR)/bpf_generic_uprobe.c
deps/bpf_generic_tracepoint_v53.d: $(PROCESSDIR)/bpf_generic_tracepoint.c
deps/bpf_vfs_rename_v419.d: $(FILEDIR)/bpf_vfs_rename.c
deps/bpf_filemap_fault_v419.d: $(FILEDIR)/bpf_filemap_fault.c
deps/bpf_filemap_map_pages_v419.d: $(FILEDIR)/bpf_filemap_map_pages.c
deps/bpf_filemap_page_mkwrite_v419.d: $(FILEDIR)/bpf_filemap_page_mkwrite.c
deps/bpf_security_file_permission_v419.d: $(FILEDIR)/bpf_security_file_permission.c
deps/bpf_vfs_unlink_v419.d: $(FILEDIR)/bpf_vfs_unlink.c
deps/bpf_security_inode_setattr_v419.d: $(FILEDIR)/bpf_security_inode_setattr.c
deps/bpf_vfs_fallocate_v419.d: $(FILEDIR)/bpf_vfs_fallocate.c
deps/bpf_finish_open_v419.d: $(FILEDIR)/bpf_finish_open.c
deps/bpf_vfs_open_v419.d: $(FILEDIR)/bpf_vfs_open.c
deps/bpf_fsnotify_v419.d: $(FILEDIR)/bpf_fsnotify.c
deps/bpf_security_inode_rmdir_v419.d: $(FILEDIR)/bpf_security_inode_rmdir.c
deps/bpf_vfs_mkdir_v419.d: $(FILEDIR)/bpf_vfs_mkdir.c
deps/bpf_iterate_dir_v419.d: $(FILEDIR)/bpf_iterate_dir.c
deps/bpf_security_bprm_check_v419.d: $(FILEDIR)/bpf_security_bprm_check.c
deps/bpf_security_path_rename_v419.d: $(FILEDIR)/bpf_security_path_rename.c
deps/bpf_security_mmap_file_lsm.d: $(FILEDIR)/bpf_security_mmap_file.c
deps/bpf_security_mmap_file_fmod.d: $(FILEDIR)/bpf_security_mmap_file.c
deps/bpf_security_inode_create_lsm.d: $(FILEDIR)/bpf_security_inode_create.c
deps/bpf_security_inode_create_fmod.d: $(FILEDIR)/bpf_security_inode_create.c
deps/bpf_iterate_dir_enforce_lsm.d: $(FILEDIR)/bpf_iterate_dir.c
deps/bpf_iterate_dir_enforce_fmod.d: $(FILEDIR)/bpf_iterate_dir.c
deps/bpf_security_file_permission_enforce_lsm.d: $(FILEDIR)/bpf_security_file_permission.c
deps/bpf_security_file_permission_enforce_fmod.d: $(FILEDIR)/bpf_security_file_permission.c
deps/bpf_security_inode_rmdir_enforce_lsm.d: $(FILEDIR)/bpf_security_inode_rmdir.c
deps/bpf_security_inode_rmdir_enforce_fmod.d: $(FILEDIR)/bpf_security_inode_rmdir.c
deps/bpf_vfs_mkdir_enforce_lsm.d: $(FILEDIR)/bpf_vfs_mkdir.c
deps/bpf_vfs_mkdir_enforce_fmod.d: $(FILEDIR)/bpf_vfs_mkdir.c
deps/bpf_vfs_unlink_enforce_lsm.d: $(FILEDIR)/bpf_vfs_unlink.c
deps/bpf_vfs_unlink_enforce_fmod.d: $(FILEDIR)/bpf_vfs_unlink.c
deps/bpf_vfs_rename_enforce_lsm.d: $(FILEDIR)/bpf_vfs_rename.c
deps/bpf_vfs_rename_enforce_fmod.d: $(FILEDIR)/bpf_vfs_rename.c
deps/bpf_security_inode_setattr_enforce_lsm.d: $(FILEDIR)/bpf_security_inode_setattr.c
deps/bpf_security_inode_setattr_enforce_fmod.d: $(FILEDIR)/bpf_security_inode_setattr.c
deps/bpf_security_inode_setattr_enforce_fmod_v60.d: $(FILEDIR)/bpf_security_inode_setattr.c
deps/bpf_security_inode_setattr_enforce_fmod_v63.d: $(FILEDIR)/bpf_security_inode_setattr.c
deps/bpf_security_bprm_check_enforce_lsm.d: $(FILEDIR)/bpf_security_bprm_check.c
deps/bpf_security_bprm_check_enforce_fmod.d: $(FILEDIR)/bpf_security_bprm_check.c
deps/bpf_security_bprm_check_enforce_lsm_digest.d: $(FILEDIR)/bpf_security_bprm_check.c
deps/bpf_security_inode_link_enforce_lsm.d: $(FILEDIR)/bpf_security_inode_link.c
deps/bpf_security_inode_link_enforce_fmod.d: $(FILEDIR)/bpf_security_inode_link.c
deps/bpf_security_inode_link_v419.d: $(FILEDIR)/bpf_security_inode_link.c
deps/bpf_security_file_open_enforce_lsm.d: $(FILEDIR)/bpf_security_file_open.c
deps/bpf_security_file_open_enforce_fmod.d: $(FILEDIR)/bpf_security_file_open.c
deps/bpf_security_file_open_v419.d: $(FILEDIR)/bpf_security_file_open.c

$(DEPSDIR)%_v419.d:
	$(CLANG) $(CLANG_FLAGS) -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@)   $< > $@

$(DEPSDIR)%_v53.d:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@)   $< > $@

objs/bpf_execve_event_v511.ll: $(ISOPROCESS)/bpf_ee_execve_event.c
objs/bpf_generic_kprobe_v511.ll: $(PROCESSDIR)/bpf_generic_kprobe.c
objs/bpf_generic_retkprobe_v511.ll: $(PROCESSDIR)/bpf_generic_retkprobe.c
objs/bpf_multi_kprobe_v511.ll: $(PROCESSDIR)/bpf_generic_kprobe.c
objs/bpf_multi_retkprobe_v511.ll: $(PROCESSDIR)/bpf_generic_retkprobe.c
objs/bpf_generic_tracepoint_v511.ll: $(PROCESSDIR)/bpf_generic_tracepoint.c
objs/bpf_generic_uprobe_v511.ll: $(PROCESSDIR)/bpf_generic_uprobe.c

objs/bpf_multi_kprobe_v511.ll objs/bpf_multi_retkprobe_v511.ll:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -D__LARGE_MAP_KEYS -D__MULTI_KPROBE -c $< -o $@

objs/%_v511.ll:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -D__LARGE_MAP_KEYS -c $< -o $@

objs/bpf_execve_event_v61.ll: $(ISOPROCESS)/bpf_ee_execve_event.c
objs/bpf_generic_kprobe_v61.ll: $(PROCESSDIR)/bpf_generic_kprobe.c
objs/bpf_generic_retkprobe_v61.ll: $(PROCESSDIR)/bpf_generic_retkprobe.c
objs/bpf_multi_kprobe_v61.ll: $(PROCESSDIR)/bpf_generic_kprobe.c
objs/bpf_multi_retkprobe_v61.ll: $(PROCESSDIR)/bpf_generic_retkprobe.c
objs/bpf_generic_tracepoint_v61.ll: $(PROCESSDIR)/bpf_generic_tracepoint.c
objs/bpf_generic_uprobe_v61.ll: $(PROCESSDIR)/bpf_generic_uprobe.c

objs/bpf_multi_kprobe_v61.ll objs/bpf_multi_retkprobe_v61.ll:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -D__LARGE_MAP_KEYS -D__V61_BPF_PROG -D__MULTI_KPROBE -c $< -o $@

objs/%_v61.ll:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -D__LARGE_MAP_KEYS -D__V61_BPF_PROG -c $< -o $@

deps/bpf_execve_event_v61.d: $(ISOPROCESS)/bpf_ee_execve_event.c
deps/bpf_generic_kprobe_v61.d: $(PROCESSDIR)/bpf_generic_kprobe.c
deps/bpf_generic_retkprobe_v61.d: $(PROCESSDIR)/bpf_generic_retkprobe.c
deps/bpf_multi_kprobe_v61.d: $(PROCESSDIR)/bpf_generic_kprobe.c
deps/bpf_multi_retkprobe_v61.d: $(PROCESSDIR)/bpf_generic_retkprobe.c
deps/bpf_generic_tracepoint_v61.d: $(PROCESSDIR)/bpf_generic_tracepoint.c
deps/bpf_generic_uprobe_v61.d: $(PROCESSDIR)/bpf_generic_uprobe.c

$(DEPSDIR)%_v61.d:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -D__LARGE_MAP_KEYS -D__V61_BPF_PROG -MM -MP -MT $(patsubst $(DEPSDIR)%.d, $(OBJSDIR)%.ll, $@)   $< > $@

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
