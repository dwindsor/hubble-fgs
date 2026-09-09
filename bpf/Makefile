include Makefile.defs

.PHONY: all clean
.SUFFIXES:

TLSDIR := parsers/tls/
HTTPDIR := parsers/http/
NOPDIR := parsers/nop/
PARSERDIR = parsers/
ALIGNCHECKERDIR = alignchecker/
ALIGNCHECKEROSSDIR = $(OSSBPFDIR)/alignchecker/
SOCKTRACKDIR := $(NETWORKINGDIR)socktrack/
ICMPDIR := $(L3DIR)icmp/
PINGDIR := $(L3DIR)ping/
IGMPDIR := $(L3DIR)igmp/
RAWSOCKDIR := $(NETWORKINGDIR)rawsock/
ISOPROCESS := process/
FILEDIR := file/
PROCESSDIR := $(OSSBPFDIR)/process/
CGROUPDIR := $(OSSBPFDIR)/cgroup/
BPFTESTDIR := $(OSSBPFDIR)/test/

ALIGNCHECKER = bpf_alignchecker.o
ALIGNCHECKEROSS = bpf_alignchecker_oss.o
PARSERS = bpf_sockops.o bpf_http.o bpf_http_verdict.o bpf_http_parser.o
TLS = bpf_tls_inet_send.o bpf_tls_skmsg.o bpf_tls_skskb_parser.o bpf_tls_skskb_verdict.o bpf_setsockopt.o
NOP = bpf_nop.o bpf_nop_verdict.o bpf_nop_parser.o

NETWORKING = bpf_kfree_skb.o bpf_fd_lookup.o bpf_fd_lookup_fentry.o bpf_fd_lookup_pstree.o bpf_fd_lookup_fentry_pstree.o

SOCKTRACK = bpf_sk_alloc.o bpf_security_sk_alloc.o

UDP = bpf_udp_bind.o bpf_udp_bind_fentry.o bpf_udp_bind_dummy.o \
      bpf_udp_inet_lazy_kp.o

TCP = bpf_tcp_close.o bpf_tcp_close_fentry.o \
      bpf_tcp_connect.o bpf_tcp_connect_fentry.o \
      bpf_tcp_security_accept_kprobe.o bpf_tcp_security_accept.o \
      bpf_tcp_listen.o bpf_tcp_listen_fentry.o \
      bpf_tcp_rst.o bpf_tcp_rst_fentry.o \
      bpf_tcp_rtt.o bpf_tcp_rtt_fentry.o \
      bpf_tcp_send_check.o \
      bpf_tcp_sockops.o

L2 = bpf_net_ns_net_exit.o

ICMP = bpf_icmp_rcv.o bpf_icmp_rcv_fentry.o
PING = bpf_pingsock_create.o bpf_pingsock_create_fentry.o
IGMP = bpf_igmp_kprobe.o bpf_igmp_fentry.o bpf_igmp_gr_kprobe.o bpf_igmp_gr_fentry.o
L3 = bpf_cgroup_net.o bpf_cgroup_net_pstree.o bpf_cgroup_net_pstree_timer.o

RAWSOCK = bpf_rawsock_create.o bpf_rawsock_create_fentry.o

# generic sensors
PROCESS = bpf_loader.o \
	  bpf_enforcer.o bpf_multi_enforcer.o bpf_fmodret_enforcer.o \
	  bpf_cgroup.o \
	  bpf_syscall.o \
	  bpf_procfs_walk.o \
	  bpf_procfs_walk_fentry.o \
	  bpf_prog_iter.o

# v4.19
# base sensor
PROCESS += bpf_execve_event.o bpf_fork.o bpf_exit.o bpf_execve_bprm_commit_creds.o
# generic probes
PROCESS += bpf_generic_kprobe.o bpf_generic_retkprobe.o bpf_generic_tracepoint.o \
           bpf_generic_uprobe.o bpf_generic_retuprobe.o bpf_generic_rawtp.o \
	   bpf_generic_usdt.o \
	   bpf_generic_fentry.o bpf_generic_fexit.o
PROCESS += bpf_generic_lsm_core.o bpf_generic_lsm_output.o

# v5.3
# base sensor
PROCESS += bpf_execve_event_v53.o
# generic probes
PROCESS += bpf_generic_kprobe_v53.o bpf_generic_retkprobe_v53.o \
	   bpf_multi_kprobe_v53.o bpf_multi_retkprobe_v53.o \
	   bpf_generic_tracepoint_v53.o \
	   bpf_generic_uprobe_v53.o bpf_generic_retuprobe_v53.o \
	   bpf_generic_rawtp_v53.o \
	   bpf_generic_usdt_v53.o \
	   bpf_generic_fentry_v53.o bpf_generic_fexit_v53.o

# v5.11
# base sensor
PROCESS += bpf_execve_event_v511.o bpf_exit_v511.o bpf_fork_v511.o
# generic probes
PROCESS += bpf_generic_kprobe_v511.o bpf_generic_retkprobe_v511.o \
	   bpf_multi_kprobe_v511.o bpf_multi_retkprobe_v511.o \
	   bpf_generic_tracepoint_v511.o \
	   bpf_generic_uprobe_v511.o bpf_generic_retuprobe_v511.o \
	   bpf_multi_uprobe_v511.o bpf_multi_retuprobe_v511.o \
	   bpf_generic_rawtp_v511.o \
	   bpf_generic_usdt_v511.o \
	   bpf_generic_fentry_v511.o bpf_generic_fexit_v511.o

# lsm
PROCESS += bpf_generic_lsm_core_v511.o bpf_generic_lsm_output_v511.o \
	bpf_generic_lsm_ima_file_v511.o bpf_generic_lsm_ima_bprm_v511.o

# v6.1
# base sensor
PROCESS += bpf_execve_event_v61.o
# generic probes
PROCESS += bpf_generic_kprobe_v61.o bpf_generic_retkprobe_v61.o \
	   bpf_multi_kprobe_v61.o bpf_multi_retkprobe_v61.o \
	   bpf_generic_tracepoint_v61.o \
	   bpf_generic_uprobe_v61.o bpf_generic_retuprobe_v61.o \
	   bpf_generic_rawtp_v61.o \
	   bpf_multi_uprobe_v61.o bpf_multi_retuprobe_v61.o \
	   bpf_generic_usdt_v61.o bpf_multi_usdt_v61.o \
	   bpf_generic_fentry_v61.o bpf_generic_fexit_v61.o

# v6.12
# base sensor
PROCESS += bpf_execve_event_v612.o
# generic probes
PROCESS += bpf_generic_kprobe_v612.o bpf_generic_retkprobe_v612.o \
           bpf_multi_kprobe_v612.o bpf_multi_retkprobe_v612.o \
           bpf_generic_tracepoint_v612.o \
           bpf_generic_uprobe_v612.o bpf_generic_retuprobe_v612.o \
           bpf_generic_rawtp_v612.o \
           bpf_multi_uprobe_v612.o bpf_multi_retuprobe_v612.o \
           bpf_generic_usdt_v612.o bpf_multi_usdt_v612.o \
           bpf_generic_fentry_v612.o bpf_generic_fexit_v612.o

# lsm
PROCESS += bpf_generic_lsm_core_v61.o bpf_generic_lsm_output_v61.o \
     bpf_generic_lsm_ima_file_v61.o bpf_generic_lsm_ima_bprm_v61.o \
     bpf_generic_lsm_core_v612.o bpf_generic_lsm_output_v612.o \
     bpf_generic_lsm_ima_file_v612.o bpf_generic_lsm_ima_bprm_v612.o

# execve_map update
PROCESS += bpf_execve_map_update.o bpf_execve_map_update_v53.o bpf_execve_map_update_v511.o \
	   bpf_execve_map_update_v61.o bpf_execve_map_update_v612.o


FILE = bpf_filemap_fault.o bpf_filemap_fault_v419.o bpf_filemap_map_pages.o bpf_filemap_map_pages_v419.o bpf_filemap_page_mkwrite.o bpf_filemap_page_mkwrite_v419.o bpf_finish_open.o bpf_finish_open_v419.o \
	  bpf_security_file_permission.o bpf_security_file_permission_v419.o bpf_security_file_permission_observe_fentry.o bpf_vfs_unlink.o bpf_vfs_unlink_v419.o bpf_vfs_fallocate.o bpf_vfs_fallocate_v419.o bpf_vfs_open.o bpf_vfs_open_v419.o \
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
	  bpf_security_inode_setattr_enforce_lsm_v60.o bpf_security_inode_setattr_enforce_lsm_v63.o \
	  bpf_security_inode_setattr_enforce_fmod_v60.o bpf_security_inode_setattr_enforce_fmod_v63.o \
	  bpf_security_bprm_check.o bpf_security_bprm_check_v419.o bpf_security_bprm_check_enforce_lsm.o bpf_security_bprm_check_enforce_fmod.o \
	  bpf_security_bprm_check_enforce_lsm_digest.o bpf_io_uring.o bpf_fsnotify.o bpf_fsnotify_v419.o bpf_lsm_check.o \
	  bpf_security_inode_link.o bpf_security_inode_link_v419.o bpf_security_inode_link_enforce_lsm.o bpf_security_inode_link_enforce_fmod.o \
	  bpf_security_file_open.o bpf_security_file_open_v419.o bpf_security_file_open_enforce_lsm.o bpf_security_file_open_enforce_fmod.o \
	  fmod_security_file_permission.o lsm_security_kernel_read_file.o lsm_security_file_open.o lsm_security_mmap_file.o lsm_security_path_link.o lsm_security_path_symlink.o \
	  lsm_security_path_mkdir.o lsm_security_path_rmdir.o lsm_security_path_unlink.o lsm_security_bprm_check.o lsm_security_path_truncate.o lsm_security_path_chmod.o lsm_security_path_chown.o lsm_security_path_rename.o \
	  probe_security_file_permission.o probe_security_path_truncate.o probe_security_file_open.o probe_security_kernel_read_file.o probe_bpf_loop.o probe_for_each_map_elem.o lsm_test_glob.o \
	  lsm_security_bprm_check_digests.o probe_bpf_ima_file_hash.o fmod_ret_dispatcher.o lsm_dispatcher_bprm_check_security.o lsm_dispatcher_kernel_read_file.o lsm_dispatcher_path_chmod.o \
	  lsm_dispatcher_path_link.o lsm_dispatcher_path_symlink.o lsm_dispatcher_path_rename.o lsm_dispatcher_path_truncate.o lsm_dispatcher_file_open.o lsm_dispatcher_mmap_file.o lsm_dispatcher_path_chown.o lsm_dispatcher_path_mkdir.o \
	  lsm_dispatcher_path_rmdir.o lsm_dispatcher_path_unlink.o fexit_getname_flags.o fexit_getname.o fexit_sys_open.o lsm_security_unix_stream_connect.o \
	  bpf_security_unix_stream_connect.o bpf_security_unix_stream_connect_v419.o bpf_security_unix_stream_connect_enforce_lsm.o bpf_security_unix_stream_connect_enforce_fmod.o \
	  bpf_vfs_mknod.o bpf_vfs_mknod_v419.o bpf_vfs_mknod_enforce_lsm.o bpf_vfs_mknod_enforce_fmod.o openraw_enforcer.o lsm_security_path_mknod.o lsm_security_bprm_creds_from_file.o

CGROUP = bpf_cgtracker.o

BPFTEST = bpf_lseek.o
BPFTEST += bpf_lseek_v511.o

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
IGMPOBJ	      := $(addprefix $(OBJSDIR),$(IGMP))
RAWSOCKOBJ    := $(addprefix $(OBJSDIR),$(RAWSOCK))
PROCESSOBJ    := $(addprefix $(OBJSDIR),$(PROCESS))
CGROUPOBJ    := $(addprefix $(OBJSDIR),$(CGROUP))
FILEOBJ       := $(addprefix $(OBJSDIR),$(FILE))
TESTOBJ       := $(addprefix $(OBJSDIR),$(BPFTEST))
ALIGNCHECKEROBJ := $(addprefix $(OBJSDIR),$(ALIGNCHECKER))
ALIGNCHECKEROSSOBJ := $(addprefix $(OBJSDIR),$(ALIGNCHECKEROSS))
OBJS          := $(PARSEROBJ) $(TLSOBJ) $(NETWORKINGOBJ) $(SOCKTRACKOBJ) $(UDPOBJ) $(TCPOBJ) $(L2OBJ) $(L3OBJ) $(PINGOBJ) $(ICMPOBJ) $(IGMPOBJ) $(RAWSOCKOBJ) $(PROCESSOBJ) $(CGROUPOBJ) $(FILEOBJ) $(TESTOBJ) $(NOPOBJ) $(ALIGNCHECKEROBJ) $(ALIGNCHECKEROSSOBJ)
DEPS          := $(patsubst $(OBJSDIR)%.o,$(DEPSDIR)%.d,$(OBJS))

all: $(OBJS) $(DEPS)

# NB: https://www.gnu.org/software/make/manual/html_node/Prerequisite-Types.html
$(OBJS): | $(OBJSDIR)
$(DEPS): | $(DEPSDIR)
$(LLOBJS): | $(OBJSDIR)

$(OBJSDIR):
	mkdir $(OBJSDIR)

$(DEPSDIR):
	mkdir $(DEPSDIR)

CFLAGS_bpf_enforcer.o             = -D__BPF_OVERRIDE_RETURN
CFLAGS_bpf_multi_enforcer.o       = -D__BPF_OVERRIDE_RETURN -D__MULTI_KPROBE
CFLAGS_bpf_multi_kprobe_v53.o     = -D__MULTI_KPROBE
CFLAGS_bpf_multi_retkprobe_v53.o  = -D__MULTI_KPROBE
CFLAGS_bpf_multi_kprobe_v511.o    = -D__MULTI_KPROBE
CFLAGS_bpf_multi_retkprobe_v511.o = -D__MULTI_KPROBE
CFLAGS_bpf_multi_kprobe_v61.o     = -D__MULTI_KPROBE
CFLAGS_bpf_multi_uprobe_v61.o     = -D__MULTI_KPROBE
CFLAGS_bpf_multi_usdt_v61.o       = -D__MULTI_KPROBE
CFLAGS_bpf_multi_retkprobe_v61.o  = -D__MULTI_KPROBE
CFLAGS_bpf_multi_kprobe_v612.o    = -D__MULTI_KPROBE
CFLAGS_bpf_multi_retkprobe_v612.o = -D__MULTI_KPROBE
CFLAGS_bpf_multi_uprobe_v612.o    = -D__MULTI_KPROBE
CFLAGS_bpf_multi_usdt_v612.o      = -D__MULTI_KPROBE
CFLAGS_bpf_generic_lsm_core.o   = -D__LARGE_BPF_PROG
CFLAGS_bpf_generic_lsm_output.o = -D__LARGE_BPF_PROG
CFLAGS_bpf_fd_lookup_pstree.o          = $(BPF_ENABLE_ATOMIC_FLAGS)
CFLAGS_bpf_fd_lookup_fentry_pstree.o   = $(BPF_ENABLE_ATOMIC_FLAGS)
CFLAGS_bpf_tcp_sockops.o               = $(BPF_ENABLE_ATOMIC_FLAGS)
CFLAGS_bpf_cgroup_net_pstree.o         = $(BPF_ENABLE_ATOMIC_FLAGS)
CFLAGS_bpf_cgroup_net_pstree_timer.o   = $(BPF_ENABLE_ATOMIC_FLAGS)

MTARGET = $(patsubst $(DEPSDIR)%.d,$(OBJSDIR)%.o,$@)

rule_d_CFLAGS = $(CFLAGS_$(notdir $(MTARGET)))
rule_o_CFLAGS = $(CFLAGS_$(notdir $@))

rule_d = $(CLANG) $(CLANG_FLAGS) $(rule_d_CFLAGS) $1 -MM -MP -MT $(MTARGET) $< > $@
rule_o = $(CLANG) $(CLANG_FLAGS) $(rule_o_CFLAGS) $1 -c $< -o $@

# Generic build targets for each sub-dir

# ALIGNCHECKER
objs/%.o: $(ALIGNCHECKERDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -c $< -o $@

$(DEPSDIR)%.d: $(ALIGNCHECKERDIR)%.c
	$(rule_d)

# ALIGNCHECKER
objs/%_oss.o:
	$(rule_o)

$(DEPSDIR)%_oss.d: $(ALIGNCHECKEROSSDIR)%.c
	$(rule_d)

# PARSERDIR
objs/%.o: $(PARSERDIR)%.c
	$(rule_o)

$(DEPSDIR)%.d: $(PARSERDIR)%.c
	$(rule_d)

# TLSDIR
objs/%.o: $(TLSDIR)%.c
	$(call rule_o,-I $(PARSERDIR))

$(DEPSDIR)%.d: $(TLSDIR)%.c
	$(rule_d)

# HTTPDIR
objs/%.o: $(HTTPDIR)%.c
	$(call rule_o,-I $(PARSERDIR))

$(DEPSDIR)%.d: $(HTTPDIR)%.c
	$(rule_d)

# NOPDIR
objs/%.o: $(NOPDIR)%.c
	$(call rule_o,-I $(NOPDIR))

$(DEPSDIR)%.d: $(NOPDIR)%.c
	$(rule_d)

# NETWORKINGDIR
objs/%.o: $(NETWORKINGDIR)%.c
	$(rule_o)

$(DEPSDIR)%.d: $(NETWORKINGDIR)%.c
	$(rule_d)

# SOCKTRACKDIR
objs/%.o: $(SOCKTRACKDIR)%.c
	$(rule_o)

$(DEPSDIR)%.d: $(SOCKTRACKDIR)%.c
	$(rule_d)

# UDPDIR
objs/%.o: $(UDPDIR)%.c
	$(rule_o)

$(DEPSDIR)%.d: $(UDPDIR)%.c
	$(rule_d)

# TCPDIR
objs/%.o: $(TCPDIR)%.c
	$(rule_o)

$(DEPSDIR)%.d: $(TCPDIR)%.c
	$(rule_d)

# L2DIR
objs/%.o: $(L2DIR)%.c
	$(rule_o)

$(DEPSDIR)%.d: $(L2DIR)%.c
	$(rule_d)

# L3DIR
objs/%.o: $(L3DIR)%.c
	$(rule_o)
	@echo "Checking for the (expected) 'canary:base_build' string in BPF object: $@"
	@if ! grep canary:base_build '$@'; then echo "Failed to find the string 'canary:base_build' in object: $@. We use this as a canary to ensure our grep works."; rm '$@'; exit 1; fi
	@if [[ "$(LSEG)" -ne 1 ]]; then echo "Checking for the (unexpected) 'canary:lseg_build' string in BPF object: $@"; if grep canary:lseg_build '$@'; then echo "Found the string 'canary:lseg_build' in object: $@. This means LSEG code is present in a non-LSEG build."; rm '$@'; exit 1; fi; fi

$(DEPSDIR)%.d: $(L3DIR)%.c
	$(rule_d)

#PING
objs/%.o: $(PINGDIR)%.c
	$(rule_o)

$(DEPSDIR)%.d: $(PINGDIR)%.c
	$(rule_d)

#ICMP
objs/%.o: $(ICMPDIR)%.c
	$(rule_o)

$(DEPSDIR)%.d: $(ICMPDIR)%.c
	$(rule_d)

#IGMP
objs/%.o: $(IGMPDIR)%.c
	$(rule_o)

$(DEPSDIR)%.d: $(IGMPDIR)%.c
	$(rule_d)

# RAWSOCKDIR
objs/%.o: $(RAWSOCKDIR)%.c
	$(rule_o)

$(DEPSDIR)%.d: $(RAWSOCKDIR)%.c
	$(rule_d)

$(DEPSDIR)%.d: $(TIMESTAMPDIR)%.c
	$(rule_d)

# PROCESSDIR
objs/%.o: $(PROCESSDIR)%.c
	$(rule_o)

# CGROUPDIR
objs/%.o: $(CGROUPDIR)%.c
	$(rule_o)

# bpf_exit: special case because the enterprise version is different than OSS
# IS_KPROBE is needed for const define on old kernels (see lib/config.h)
objs/bpf_exit.o: $(ISOPROCESS)bpf_exit.c
	$(CLANG) $(CLANG_FLAGS) -DIS_KPROBE -c $< -o $@

deps/bpf_exit.d: $(ISOPROCESS)bpf_exit.c
	$(rule_d)

# bpf_ee_execve_event: special case because the enterprise version is different than OSS
# IS_KPROBE is needed for const define on old kernels (see lib/config.h)
objs/bpf_execve_event.o: $(ISOPROCESS)bpf_ee_execve_event.c
	$(CLANG) $(CLANG_FLAGS) -DIS_KPROBE -c $< -o $@

deps/bpf_execve_event.d: $(ISOPROCESS)bpf_ee_execve_event.c
	$(rule_d)

objs/bpf_syscall.o: $(ISOPROCESS)bpf_syscall.c $(ISOPROCESS)process_syscall.h
	$(CLANG) $(CLANG_FLAGS) -c $< -o $@

deps/bpf_syscall.d: $(ISOPROCESS)bpf_syscall.c
	$(rule_d)

objs/bpf_procfs_walk.o: $(ISOPROCESS)bpf_procfs_walk.c $(ISOPROCESS)procfs_walk.h
	$(rule_o)

deps/bpf_procfs_walk.d: $(ISOPROCESS)bpf_procfs_walk.c
	$(rule_d)

objs/bpf_procfs_walk_fentry.o: $(ISOPROCESS)bpf_procfs_walk_fentry.c $(ISOPROCESS)procfs_walk.h
	$(rule_o)

deps/bpf_procfs_walk_fentry.d: $(ISOPROCESS)bpf_procfs_walk_fentry.c
	$(rule_d)

## bpf_enforcer: __BPF_OVERRIDE_RETURN, but no __MULTI_KPROBE
objs/bpf_enforcer.o: $(PROCESSDIR)/bpf_enforcer.c
	$(rule_o)

$(DEPSDIR)bpf_enforcer.d: $(PROCESSDIR)/bpf_enforcer.c
	$(rule_d)

## bpf_multi_enforcer: __BPF_OVERRIDE_RETURN and __MULTI_KPROBE
objs/bpf_multi_enforcer.o: $(PROCESSDIR)/bpf_enforcer.c
	$(call rule_o,-D__BPF_OVERRIDE_RETURN -D__MULTI_KPROBE)

$(DEPSDIR)/bpf_multi_enforcer.d: $(PROCESSDIR)/bpf_enforcer.c
	$(call rule_o,-D__BPF_OVERRIDE_RETURN -D__MULTI_KPROBE)

## bpf_fmodret_enforcer no bpf_override_return: we need fmod_ret
objs/bpf_fmodret_enforcer.o: $(PROCESSDIR)/bpf_enforcer.c
	$(rule_o)

$(DEPSDIR)/bpf_fmodret_enforcer.d: $(PROCESSDIR)/bpf_enforcer.c
	$(rule_d)

# FILEDIR
objs/%.o: $(FILEDIR)%.c
	$(call rule_o,-D__LARGE_BPF_PROG)

objs/%_lsm.o:
	$(call rule_o,-D__LARGE_BPF_PROG -D__FILE_ENFORCE_LSM)

$(DEPSDIR)%_lsm.d:
	$(call rule_d,-D__LARGE_BPF_PROG -D__FILE_ENFORCE_LSM)

objs/%_observe_fentry.o: $(FILEDIR)%.c
	$(call rule_o,-D__LARGE_BPF_PROG -D__FILE_FENTRY)

$(DEPSDIR)%_observe_fentry.d: $(FILEDIR)%.c
	$(call rule_d,-D__LARGE_BPF_PROG -D__FILE_FENTRY)

objs/%_lsm_digest.o:
	$(call rule_o,-D__LARGE_BPF_PROG -D__FILE_ENFORCE_LSM -D__FILE_DIGEST_LSM)

$(DEPSDIR)%_lsm_digest.d:
	$(call rule_d,-D__LARGE_BPF_PROG -D__FILE_ENFORCE_LSM -D__FILE_DIGEST_LSM)

objs/%_fmod.o:
	$(call rule_o,-D__LARGE_BPF_PROG -D__FILE_ENFORCE_FMOD)

$(DEPSDIR)%_fmod.d:
	$(call rule_d,-D__LARGE_BPF_PROG -D__FILE_ENFORCE_FMOD)

objs/%_lsm_v60.o:
	$(call rule_o,-D__LARGE_BPF_PROG -D__FILE_ENFORCE_LSM -D__V60_BPF_PROG)

$(DEPSDIR)%_lsm_v60.d:
	$(call rule_d,-D__LARGE_BPF_PROG -D__FILE_ENFORCE_LSM -D__V60_BPF_PROG)

objs/%_fmod_v60.o:
	$(call rule_o,-D__LARGE_BPF_PROG -D__FILE_ENFORCE_FMOD -D__V60_BPF_PROG)

$(DEPSDIR)%_fmod_v60.d:
	$(call rule_d,-D__LARGE_BPF_PROG -D__FILE_ENFORCE_FMOD -D__V60_BPF_PROG)

objs/%_lsm_v63.o:
	$(call rule_o,-D__LARGE_BPF_PROG -D__FILE_ENFORCE_LSM -D__V63_BPF_PROG)

$(DEPSDIR)%_lsm_v63.d:
	$(call rule_d,-D__LARGE_BPF_PROG -D__FILE_ENFORCE_LSM -D__V63_BPF_PROG)

objs/%_fmod_v63.o:
	$(call rule_o,-D__LARGE_BPF_PROG -D__FILE_ENFORCE_FMOD -D__V63_BPF_PROG)

$(DEPSDIR)%_fmod_v63.d:
	$(call rule_d,-D__LARGE_BPF_PROG -D__FILE_ENFORCE_FMOD -D__V63_BPF_PROG)

objs/bpf_execve_event_v612.o: $(ISOPROCESS)/bpf_ee_execve_event_notc.c
objs/bpf_execve_event_v511.o: $(ISOPROCESS)/bpf_ee_execve_event_notc.c
objs/bpf_execve_event_v53.o: $(ISOPROCESS)/bpf_ee_execve_event_notc.c
objs/bpf_fork_v511.o: $(PROCESSDIR)/bpf_fork.c
objs/bpf_exit_v511.o: $(ISOPROCESS)bpf_exit.c
objs/bpf_generic_kprobe_v53.o: $(PROCESSDIR)/bpf_generic_kprobe.c
objs/bpf_generic_retkprobe_v53.o: $(PROCESSDIR)/bpf_generic_retkprobe.c
objs/bpf_multi_kprobe_v53.o: $(PROCESSDIR)/bpf_generic_kprobe.c
objs/bpf_multi_retkprobe_v53.o: $(PROCESSDIR)/bpf_generic_retkprobe.c
objs/bpf_generic_uprobe_v53.o: $(PROCESSDIR)/bpf_generic_uprobe.c
objs/bpf_generic_retuprobe_v53.o: $(PROCESSDIR)/bpf_generic_retuprobe.c
objs/bpf_generic_usdt_v53.o: $(PROCESSDIR)/bpf_generic_usdt.c
objs/bpf_generic_tracepoint_v53.o: $(PROCESSDIR)/bpf_generic_tracepoint.c
objs/bpf_generic_rawtp_v53.o: $(PROCESSDIR)/bpf_generic_rawtp.c
objs/bpf_vfs_rename_v419.o: $(FILEDIR)/bpf_vfs_rename.c
objs/bpf_filemap_fault_v419.o: $(FILEDIR)/bpf_filemap_fault.c
objs/bpf_filemap_map_pages_v419.o: $(FILEDIR)/bpf_filemap_map_pages.c
objs/bpf_filemap_page_mkwrite_v419.o: $(FILEDIR)/bpf_filemap_page_mkwrite.c
objs/bpf_security_file_permission_v419.o: $(FILEDIR)/bpf_security_file_permission.c
objs/bpf_vfs_unlink_v419.o: $(FILEDIR)/bpf_vfs_unlink.c
objs/security_unix_stream_connect_v419.o: $(FILEDIR)/bpf_security_unix_stream_connect.c
objs/vfs_mknod_v419.o: $(FILEDIR)/bpf_vfs_mknod.c
objs/bpf_security_inode_setattr_v419.o: $(FILEDIR)/bpf_security_inode_setattr.c
objs/bpf_vfs_fallocate_v419.o: $(FILEDIR)/bpf_vfs_fallocate.c
objs/bpf_finish_open_v419.o: $(FILEDIR)/bpf_finish_open.c
objs/bpf_vfs_open_v419.o: $(FILEDIR)/bpf_vfs_open.c
objs/bpf_fsnotify_v419.o: $(FILEDIR)/bpf_fsnotify.c
objs/bpf_security_inode_rmdir_v419.o: $(FILEDIR)/bpf_security_inode_rmdir.c
objs/bpf_vfs_mkdir_v419.o: $(FILEDIR)/bpf_vfs_mkdir.c
objs/bpf_iterate_dir_v419.o: $(FILEDIR)/bpf_iterate_dir.c
objs/bpf_security_bprm_check_v419.o: $(FILEDIR)/bpf_security_bprm_check.c
objs/bpf_security_path_rename_v419.o: $(FILEDIR)/bpf_security_path_rename.c
objs/bpf_security_inode_link_v419.o: $(FILEDIR)/bpf_security_inode_link.c
objs/bpf_security_file_open_v419.o: $(FILEDIR)/bpf_security_file_open.c
objs/bpf_execve_map_update_v53.o: $(PROCESSDIR)/bpf_execve_map_update.c
objs/bpf_execve_map_update_v511.o: $(PROCESSDIR)/bpf_execve_map_update.c
objs/bpf_execve_map_update_v61.o: $(PROCESSDIR)/bpf_execve_map_update.c
objs/bpf_execve_map_update_v612.o: $(PROCESSDIR)/bpf_execve_map_update.c

objs/bpf_multi_kprobe_v53.o objs/bpf_multi_retkprobe_v53.o:
	$(call rule_o,-D__LARGE_BPF_PROG -D__MULTI_KPROBE)

objs/%_v419.o:
	$(rule_o)

objs/%_v53.o:
	$(call rule_o,-D__LARGE_BPF_PROG)

objs/%_v511.o:
	$(CLANG) $(CLANG_FLAGS) -D__LARGE_BPF_PROG -D__V511_BPF_PROG -c $< -o $@

$(DEPSDIR)%.d: $(PROCESSDIR)%.c
	$(rule_d)

$(DEPSDIR)%.d: $(CGROUPDIR)%.c
	$(rule_d)

deps/bpf_execve_event_v511.d: $(ISOPROCESS)/bpf_ee_execve_event_notc.c
deps/bpf_generic_kprobe_v511.d: $(PROCESSDIR)/bpf_generic_kprobe.c
deps/bpf_generic_lsm_core_v511.d: $(PROCESSDIR)/bpf_generic_lsm_core.c
deps/bpf_generic_lsm_output_v511.d: $(PROCESSDIR)/bpf_generic_lsm_output.c
deps/bpf_generic_lsm_ima_file_v511.d: $(PROCESSDIR)/bpf_generic_lsm_ima_file.c
deps/bpf_generic_lsm_ima_bprm_v511.d: $(PROCESSDIR)/bpf_generic_lsm_ima_bprm.c
deps/bpf_generic_retkprobe_v511.d: $(PROCESSDIR)/bpf_generic_retkprobe.c
deps/bpf_multi_kprobe_v511.d: $(PROCESSDIR)/bpf_generic_kprobe.c
deps/bpf_multi_retkprobe_v511.d: $(PROCESSDIR)/bpf_generic_retkprobe.c
deps/bpf_generic_uprobe_v511.d: $(PROCESSDIR)/bpf_generic_uprobe.c
deps/bpf_generic_usdt_v511.d: $(PROCESSDIR)/bpf_generic_usdt.c
deps/bpf_generic_usdt_v53.d: $(PROCESSDIR)/bpf_generic_usdt.c
deps/bpf_multi_uprobe_v511.d: $(PROCESSDIR)/bpf_generic_uprobe.c
deps/bpf_generic_retuprobe_v511.d: $(PROCESSDIR)/bpf_generic_retuprobe.c
deps/bpf_multi_retuprobe_v511.d: $(PROCESSDIR)/bpf_generic_retuprobe.c
deps/bpf_generic_tracepoint_v511.d: $(PROCESSDIR)/bpf_generic_tracepoint.c
deps/bpf_generic_rawtp_v511.d: $(PROCESSDIR)/bpf_generic_rawtp.c
deps/bpf_generic_fentry_v511.d: $(PROCESSDIR)/bpf_generic_fentry.c
deps/bpf_generic_fexit_v511.d: $(PROCESSDIR)/bpf_generic_fexit.c
deps/bpf_fork_v511.d: $(PROCESSDIR)/bpf_fork.c
deps/bpf_exit_v511.d: $(ISOPROCESS)/bpf_exit.c
deps/bpf_execve_event_v53.d: $(ISOPROCESS)/bpf_ee_execve_event_notc.c
deps/bpf_generic_kprobe_v53.d: $(PROCESSDIR)/bpf_generic_kprobe.c
deps/bpf_generic_retkprobe_v53.d: $(PROCESSDIR)/bpf_generic_retkprobe.c
deps/bpf_multi_kprobe_v53.d: $(PROCESSDIR)/bpf_generic_kprobe.c
deps/bpf_multi_retkprobe_v53.d: $(PROCESSDIR)/bpf_generic_retkprobe.c
deps/bpf_generic_uprobe_v53.d: $(PROCESSDIR)/bpf_generic_uprobe.c
deps/bpf_generic_retuprobe_v53.d: $(PROCESSDIR)/bpf_generic_retuprobe.c
deps/bpf_generic_usdt.d: $(PROCESSDIR)/bpf_generic_usdt.c
deps/bpf_generic_tracepoint_v53.d: $(PROCESSDIR)/bpf_generic_tracepoint.c
deps/bpf_generic_rawtp_v53.d: $(PROCESSDIR)/bpf_generic_rawtp.c
deps/bpf_generic_fentry_v53.d: $(PROCESSDIR)/bpf_generic_fentry.c
deps/bpf_generic_fexit_v53.d: $(PROCESSDIR)/bpf_generic_fexit.c
deps/bpf_vfs_rename_v419.d: $(FILEDIR)/bpf_vfs_rename.c
deps/bpf_filemap_fault_v419.d: $(FILEDIR)/bpf_filemap_fault.c
deps/bpf_filemap_map_pages_v419.d: $(FILEDIR)/bpf_filemap_map_pages.c
deps/bpf_filemap_page_mkwrite_v419.d: $(FILEDIR)/bpf_filemap_page_mkwrite.c
deps/bpf_security_file_permission_v419.d: $(FILEDIR)/bpf_security_file_permission.c
deps/bpf_vfs_unlink_v419.d: $(FILEDIR)/bpf_vfs_unlink.c
deps/bpf_security_unix_stream_connect_v419.d: $(FILEDIR)/bpf_security_unix_stream_connect.c
deps/bpf_vfs_mknod_v419.d: $(FILEDIR)/bpf_vfs_mknod.c
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
deps/bpf_security_unix_stream_connect_enforce_lsm.d: $(FILEDIR)/bpf_security_unix_stream_connect.c
deps/bpf_security_unix_stream_connect_enforce_fmod.d: $(FILEDIR)/bpf_security_unix_stream_connect.c
deps/bpf_vfs_mknod_enforce_lsm.d: $(FILEDIR)/bpf_vfs_mknod.c
deps/bpf_vfs_mknod_enforce_fmod.d: $(FILEDIR)/bpf_vfs_mknod.c
deps/bpf_vfs_rename_enforce_lsm.d: $(FILEDIR)/bpf_vfs_rename.c
deps/bpf_vfs_rename_enforce_fmod.d: $(FILEDIR)/bpf_vfs_rename.c
deps/bpf_security_inode_setattr_enforce_lsm.d: $(FILEDIR)/bpf_security_inode_setattr.c
deps/bpf_security_inode_setattr_enforce_lsm_v60.d: $(FILEDIR)/bpf_security_inode_setattr.c
deps/bpf_security_inode_setattr_enforce_lsm_v63.d: $(FILEDIR)/bpf_security_inode_setattr.c
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
	$(rule_d)

$(DEPSDIR)%_v53.d:
	$(call rule_d,-D__LARGE_BPF_PROG)

$(DEPSDIR)%_v511.d:
	$(call rule_d,-D__LARGE_BPF_PROG -D__V511_BPF_PROG)

objs/bpf_execve_event_v511.o: $(ISOPROCESS)/bpf_ee_execve_event_notc.c
objs/bpf_generic_kprobe_v511.o: $(PROCESSDIR)/bpf_generic_kprobe.c

objs/bpf_generic_lsm_core_v511.o: $(PROCESSDIR)/bpf_generic_lsm_core.c
objs/bpf_generic_lsm_output_v511.o: $(PROCESSDIR)/bpf_generic_lsm_output.c
objs/bpf_generic_lsm_ima_file_v511.o: $(PROCESSDIR)/bpf_generic_lsm_ima_file.c
objs/bpf_generic_lsm_ima_bprm_v511.o: $(PROCESSDIR)/bpf_generic_lsm_ima_bprm.c

objs/bpf_generic_retkprobe_v511.o: $(PROCESSDIR)/bpf_generic_retkprobe.c
objs/bpf_multi_kprobe_v511.o: $(PROCESSDIR)/bpf_generic_kprobe.c
objs/bpf_multi_retkprobe_v511.o: $(PROCESSDIR)/bpf_generic_retkprobe.c
objs/bpf_generic_tracepoint_v511.o: $(PROCESSDIR)/bpf_generic_tracepoint.c
objs/bpf_generic_rawtp_v511.o: $(PROCESSDIR)/bpf_generic_rawtp.c
objs/bpf_generic_uprobe_v511.o: $(PROCESSDIR)/bpf_generic_uprobe.c
objs/bpf_generic_usdt_v511.o: $(PROCESSDIR)/bpf_generic_usdt.c
objs/bpf_multi_uprobe_v511.o: $(PROCESSDIR)/bpf_generic_uprobe.c
objs/bpf_generic_retuprobe_v511.o: $(PROCESSDIR)/bpf_generic_retuprobe.c
objs/bpf_multi_retuprobe_v511.o: $(PROCESSDIR)/bpf_generic_retuprobe.c
objs/bpf_generic_usdt.o: $(PROCESSDIR)/bpf_generic_usdt.c
objs/bpf_generic_fentry_v511.o: $(PROCESSDIR)/bpf_generic_fentry.c
objs/bpf_generic_fexit_v511.o: $(PROCESSDIR)/bpf_generic_fexit.c

objs/bpf_multi_kprobe_v511.o objs/bpf_multi_retkprobe_v511.o:
	$(call rule_o,-D__LARGE_BPF_PROG -D__V511_BPF_PROG -D__MULTI_KPROBE)

objs/%_v511.o:
	$(call rule_o,-D__V511_BPF_PROG -D__LARGE_BPF_PROG -D__V511_BPF_PROG)

objs/bpf_execve_event_v61.o: $(ISOPROCESS)/bpf_ee_execve_event_notc.c
objs/bpf_generic_kprobe_v61.o: $(PROCESSDIR)/bpf_generic_kprobe.c
objs/bpf_generic_lsm_core_v61.o: $(PROCESSDIR)/bpf_generic_lsm_core.c
objs/bpf_generic_lsm_output_v61.o: $(PROCESSDIR)/bpf_generic_lsm_output.c
objs/bpf_generic_lsm_ima_file_v61.o: $(PROCESSDIR)/bpf_generic_lsm_ima_file.c
objs/bpf_generic_lsm_ima_bprm_v61.o: $(PROCESSDIR)/bpf_generic_lsm_ima_bprm.c
objs/bpf_generic_retkprobe_v61.o: $(PROCESSDIR)/bpf_generic_retkprobe.c
objs/bpf_multi_kprobe_v61.o: $(PROCESSDIR)/bpf_generic_kprobe.c
objs/bpf_multi_retkprobe_v61.o: $(PROCESSDIR)/bpf_generic_retkprobe.c
objs/bpf_generic_tracepoint_v61.o: $(PROCESSDIR)/bpf_generic_tracepoint.c
objs/bpf_generic_rawtp_v61.o: $(PROCESSDIR)/bpf_generic_rawtp.c
objs/bpf_generic_uprobe_v61.o: $(PROCESSDIR)/bpf_generic_uprobe.c
objs/bpf_multi_uprobe_v61.o: $(PROCESSDIR)/bpf_generic_uprobe.c
objs/bpf_generic_retuprobe_v61.o: $(PROCESSDIR)/bpf_generic_retuprobe.c
objs/bpf_multi_retuprobe_v61.o: $(PROCESSDIR)/bpf_generic_retuprobe.c
objs/bpf_generic_usdt_v61.o: $(PROCESSDIR)/bpf_generic_usdt.c
objs/bpf_multi_usdt_v61.o: $(PROCESSDIR)/bpf_generic_usdt.c
objs/bpf_generic_fentry_v61.o: $(PROCESSDIR)/bpf_generic_fentry.c
objs/bpf_generic_fexit_v61.o: $(PROCESSDIR)/bpf_generic_fexit.c

objs/bpf_multi_kprobe_v61.o objs/bpf_multi_retkprobe_v61.o:
	$(call rule_o,-D__LARGE_BPF_PROG -D__V511_BPF_PROG -D__V61_BPF_PROG -D__MULTI_KPROBE)

objs/%_v61.o:
	$(call rule_o,-D__LARGE_BPF_PROG -D__V511_BPF_PROG -D__V61_BPF_PROG)

deps/bpf_execve_event_v61.d: $(ISOPROCESS)/bpf_ee_execve_event_notc.c
deps/bpf_generic_kprobe_v61.d: $(PROCESSDIR)/bpf_generic_kprobe.c
deps/bpf_generic_lsm_core_v61.d: $(PROCESSDIR)/bpf_generic_lsm_core.c
deps/bpf_generic_lsm_output_v61.d: $(PROCESSDIR)/bpf_generic_lsm_output.c
deps/bpf_generic_lsm_ima_file_v61.d: $(PROCESSDIR)/bpf_generic_lsm_ima_file.c
deps/bpf_generic_lsm_ima_bprm_v61.d: $(PROCESSDIR)/bpf_generic_lsm_ima_bprm.c
deps/bpf_generic_retkprobe_v61.d: $(PROCESSDIR)/bpf_generic_retkprobe.c
deps/bpf_multi_kprobe_v61.d: $(PROCESSDIR)/bpf_generic_kprobe.c
deps/bpf_multi_retkprobe_v61.d: $(PROCESSDIR)/bpf_generic_retkprobe.c
deps/bpf_generic_tracepoint_v61.d: $(PROCESSDIR)/bpf_generic_tracepoint.c
deps/bpf_generic_rawtp_v61.d: $(PROCESSDIR)/bpf_generic_rawtp.c
deps/bpf_generic_uprobe_v61.d: $(PROCESSDIR)/bpf_generic_uprobe.c
deps/bpf_multi_uprobe_v61.d: $(PROCESSDIR)/bpf_generic_uprobe.c
deps/bpf_generic_retuprobe_v61.d: $(PROCESSDIR)/bpf_generic_retuprobe.c
deps/bpf_multi_retuprobe_v61.d: $(PROCESSDIR)/bpf_generic_retuprobe.c
deps/bpf_generic_usdt_v61.d: $(PROCESSDIR)/bpf_generic_usdt.c
deps/bpf_multi_usdt_v61.d: $(PROCESSDIR)/bpf_generic_usdt.c
deps/bpf_generic_fentry_v61.d: $(PROCESSDIR)/bpf_generic_fentry.c
deps/bpf_generic_fexit_v61.d: $(PROCESSDIR)/bpf_generic_fexit.c

$(DEPSDIR)%_v61.d:
	$(call rule_d,-D__LARGE_BPF_PROG -D__V511_BPF_PROG -D__V61_BPF_PROG)

objs/bpf_execve_event_v612.o: $(ISOPROCESS)/bpf_ee_execve_event_notc.c
objs/bpf_generic_kprobe_v612.o: $(PROCESSDIR)/bpf_generic_kprobe.c
objs/bpf_generic_lsm_core_v612.o: $(PROCESSDIR)/bpf_generic_lsm_core.c
objs/bpf_generic_lsm_output_v612.o: $(PROCESSDIR)/bpf_generic_lsm_output.c
objs/bpf_generic_lsm_ima_file_v612.o: $(PROCESSDIR)/bpf_generic_lsm_ima_file.c
objs/bpf_generic_lsm_ima_bprm_v612.o: $(PROCESSDIR)/bpf_generic_lsm_ima_bprm.c
objs/bpf_generic_retkprobe_v612.o: $(PROCESSDIR)/bpf_generic_retkprobe.c
objs/bpf_multi_kprobe_v612.o: $(PROCESSDIR)/bpf_generic_kprobe.c
objs/bpf_multi_retkprobe_v612.o: $(PROCESSDIR)/bpf_generic_retkprobe.c
objs/bpf_generic_tracepoint_v612.o: $(PROCESSDIR)/bpf_generic_tracepoint.c
objs/bpf_generic_rawtp_v612.o: $(PROCESSDIR)/bpf_generic_rawtp.c
objs/bpf_generic_uprobe_v612.o: $(PROCESSDIR)/bpf_generic_uprobe.c
objs/bpf_multi_uprobe_v612.o: $(PROCESSDIR)/bpf_generic_uprobe.c
objs/bpf_generic_retuprobe_v612.o: $(PROCESSDIR)/bpf_generic_retuprobe.c
objs/bpf_multi_retuprobe_v612.o: $(PROCESSDIR)/bpf_generic_retuprobe.c
objs/bpf_generic_usdt_v612.o: $(PROCESSDIR)/bpf_generic_usdt.c
objs/bpf_multi_usdt_v612.o: $(PROCESSDIR)/bpf_generic_usdt.c
objs/bpf_generic_fentry_v612.o: $(PROCESSDIR)/bpf_generic_fentry.c
objs/bpf_generic_fexit_v612.o: $(PROCESSDIR)/bpf_generic_fexit.c

objs/bpf_multi_kprobe_v612.o objs/bpf_multi_retkprobe_v612.o:
	$(call rule_o,-D__LARGE_BPF_PROG -D__V511_BPF_PROG -D__V61_BPF_PROG -D__V612_BPF_PROG -D__MULTI_KPROBE)

objs/%_v612.o:
	$(call rule_o,-D__LARGE_BPF_PROG -D__V511_BPF_PROG -D__V61_BPF_PROG -D__V612_BPF_PROG)

deps/bpf_execve_event_v612.d: $(ISOPROCESS)/bpf_ee_execve_event_notc.c
deps/bpf_generic_kprobe_v612.d: $(PROCESSDIR)/bpf_generic_kprobe.c
deps/bpf_generic_lsm_core_v612.d: $(PROCESSDIR)/bpf_generic_lsm_core.c
deps/bpf_generic_lsm_output_v612.d: $(PROCESSDIR)/bpf_generic_lsm_output.c
deps/bpf_generic_lsm_ima_file_v612.d: $(PROCESSDIR)/bpf_generic_lsm_ima_file.c
deps/bpf_generic_lsm_ima_bprm_v612.d: $(PROCESSDIR)/bpf_generic_lsm_ima_bprm.c
deps/bpf_generic_retkprobe_v612.d: $(PROCESSDIR)/bpf_generic_retkprobe.c
deps/bpf_multi_kprobe_v612.d: $(PROCESSDIR)/bpf_generic_kprobe.c
deps/bpf_multi_retkprobe_v612.d: $(PROCESSDIR)/bpf_generic_retkprobe.c
deps/bpf_generic_tracepoint_v612.d: $(PROCESSDIR)/bpf_generic_tracepoint.c
deps/bpf_generic_rawtp_v612.d: $(PROCESSDIR)/bpf_generic_rawtp.c
deps/bpf_generic_uprobe_v612.d: $(PROCESSDIR)/bpf_generic_uprobe.c
deps/bpf_multi_uprobe_v612.d: $(PROCESSDIR)/bpf_generic_uprobe.c
deps/bpf_generic_retuprobe_v612.d: $(PROCESSDIR)/bpf_generic_retuprobe.c
deps/bpf_multi_retuprobe_v612.d: $(PROCESSDIR)/bpf_generic_retuprobe.c
deps/bpf_generic_usdt_v612.d: $(PROCESSDIR)/bpf_generic_usdt.c
deps/bpf_multi_usdt_v612.d: $(PROCESSDIR)/bpf_generic_usdt.c
deps/bpf_generic_fentry_v612.d: $(PROCESSDIR)/bpf_generic_fentry.c
deps/bpf_generic_fexit_v612.d: $(PROCESSDIR)/bpf_generic_fexit.c
deps/bpf_execve_map_update_v53.d: $(PROCESSDIR)/bpf_execve_map_update.c
deps/bpf_execve_map_update_v511.d: $(PROCESSDIR)/bpf_execve_map_update.c
deps/bpf_execve_map_update_v61.d: $(PROCESSDIR)/bpf_execve_map_update.c
deps/bpf_execve_map_update_v612.d: $(PROCESSDIR)/bpf_execve_map_update.c

$(DEPSDIR)%_v612.d:
	$(call rule_d,-D__LARGE_BPF_PROG -D__V511_BPF_PROG -D__V61_BPF_PROG -D__V612_BPF_PROG)

# BPFTESTDIR
objs/bpf_lseek_v511.o: $(BPFTESTDIR)bpf_lseek.c
objs/%.o: $(BPFTESTDIR)%.c
	$(CLANG) $(CLANG_FLAGS) -c $< -o $@

deps/bpf_lseek_v511.d: $(BPFTESTDIR)bpf_lseek.c
$(DEPSDIR)%.d: $(BPFTESTDIR)%.c
	$(rule_d)

objs/%.o:
	$(rule_o)

# include dependencies, see https://lists.gnu.org/archive/html/make-w32/2004-03/msg00062.html
ifeq (,$(filter $(MAKECMDGOALS),clean test))
-include $(DEPS)
endif

test:
	$(MAKE) -C tests test

SUBDIRS=tests

clean:
	@$(ECHO_CLEAN)
	$(QUIET) $(foreach TARGET,$(SUBDIRS), \
		$(MAKE) -C $(TARGET) clean)
	$(QUIET)rm -f $(OBJSDIR)*.{o,ll,i,s}
	$(QUIET)rm -f $(DEPSDIR)*.d
	make -C $(OSSBPFDIR) clean
