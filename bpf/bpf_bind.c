#include "vmlinux.h"

#ifndef bpf_map_def
struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};
#endif

#include "api.h"
#include "hubble_msg.h"
#include "bpf_events.h"

char _license[] __attribute__((section(("license")), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int  _version __attribute__((section(("version")), used)) = VMLINUX_KERNEL_VERSION;
#endif

__attribute__((section(("kprobe/sys_bind")), used))
int event_bind(struct pt_regs *ctx)
{
	struct msg_ipv4_tcp_connect *msg = 0;
	struct event_execve *curr, *parent;

	struct task_struct *task;

	struct sockaddr_in *in_addr;

	struct nsproxy *nsproxy;
	struct css_set *cgroups;
	struct cgroup *cgrp;
	struct net *net_ns;
	struct kernfs_node *kn;
	struct cgroup_subsys_state *subsys;

	char *addr;
	const char *name;

	bool walker = 0;
	__u32 ppid = 0;
	uint64_t size;

#define AF_UNSPEC 0
#define AF_INET 2

	msg = event_find_curr(&ppid, &walker);
	if (!msg) {
		struct msg_ipv4_tcp_connect *parent_event;
		struct event_execve *parent;
		int zero = 0;

		msg = map_lookup_elem(&msg_ipv4_tcp_map, &zero);
		if (!msg)
			return 0;
		parent = (struct event_execve *)msg->pid;
		parent_event = event_find_parent();
		if (parent_event)
			event_copy_execve(parent,
					  (struct event_execve *)&parent_event->pid);
		else
			event_minimal_parent(parent);
		size = validate_arg_size(parent->size);
		curr = (void *)parent + size;
		msg->common.size = 1;
		event_minimal_curr(curr);
	}

	probe_read(&in_addr, sizeof(in_addr), &ctx->si);
	if (in_addr) {
		__u8 family = 0;

		probe_read(&family, sizeof(family), &in_addr->sin_family);
		if (family == AF_INET || family == AF_UNSPEC) {
			probe_read(&msg->tuple.proto, sizeof(msg->tuple.proto), &(in_addr->sin_family));
			probe_read(&msg->tuple.saddr, sizeof(msg->tuple.saddr), &(in_addr->sin_addr.s_addr));
			probe_read(&msg->tuple.sport, sizeof(msg->tuple.sport), &(in_addr->sin_port));
		}
	}

	msg->common.op = MSG_OP_IPV4_BIND;
	msg->common.ktime = ktime_get_ns();
	parent = (struct event_execve *)&msg->pid;

	if (parent->flags & EVENT_NEEDS_AUID) {
		__u32 flags = parent->flags & ~EVENT_NEEDS_AUID;

		parent->auid = get_auid();
		parent->flags = flags;
	}
	size = validate_arg_size(parent->size);
	curr = (void *)parent + size;
	if (curr->flags & EVENT_NEEDS_AUID) {
		__u32 flags = curr->flags & ~EVENT_NEEDS_AUID;

		curr->auid = get_auid();
		curr->flags = flags;
	}
	msg->common.size = offsetof(struct msg_ipv4_tcp_connect, pid) + parent->size + curr->size;
	curr->uid = get_current_uid_gid();
	if (walker)
		curr->flags |= EVENT_TASK_WALK;

	task = (struct task_struct *)get_current_task();
	probe_read(&nsproxy, sizeof(nsproxy), &(task->nsproxy));
	if (nsproxy) {
		probe_read(&net_ns, sizeof(net_ns), &(nsproxy->net_ns));
		if (net_ns)
			probe_read(&msg->kube.net_ns, sizeof(msg->kube.net_ns), &(net_ns->ns.inum));
	}

#ifdef BPF_FUNC_get_current_cgroup_id
	msg->kube.cgrpid = get_current_cgroup_id();
#endif
/* Pahole bug does not convert to btf correctly with arbitrary byte holes not
 * near a cacheline. To work-around this we can specify a define with the
 * CGROUPS_OFFSET we read directly out of debug_info section. Note other
 * reads, subsys[], cgroup are the first element of the structure so we can
 * "just" read those. Then cid, kn, and name all appear to be before byte
 * holes on kernels I checked so leave them alone for now.
 *
 * Todo, fix pahole to avoid doing extra steps to lookup offsets.
 */
	task = (struct task_struct *)get_current_task();
#ifdef CGROUPS_OFFSET
	addr = (void *)task;
	addr += CGROUPS_OFFSET;
#else
	addr = (void *)&(task->cgroups);
#endif
	probe_read(&cgroups, sizeof(cgroups), addr);
	if (cgroups) {
		probe_read(&subsys, sizeof(subsys), &(cgroups->subsys[0]));
		if (subsys) {
			probe_read(&cgrp, sizeof(cgrp), &(subsys->cgroup));
			if (cgrp) {
#ifdef CGROUPS_KN_OFFSET
				addr = (void *)(cgrp);
				addr += CGROUPS_KN_OFFSET;
#else
				addr = (void *)&(cgrp->kn);
#endif
				probe_read(&kn, sizeof(cgrp->kn), addr);
				if (kn) {
					probe_read(&name, sizeof(name), &(kn->name));
					if (name)
						probe_read_str(msg->kube.docker_id,
							       DOCKER_ID_LENGTH,
							       name);
				}
			}
		}
	}

	size = validate_msg_size(msg->common.size);
	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, msg, size);
	return 1;
}
