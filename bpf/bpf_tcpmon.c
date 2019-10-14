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

#ifdef BTF
struct {
	unsigned int (*type)[BPF_MAP_TYPE_PERF_EVENT_ARRAY];
	unsigned int (*key_size)[sizeof(int)];
	unsigned int (*value_size)[sizeof(struct event)];
} tcpmon_map __attribute__((section((".maps")), used));
#else
struct bpf_map_def __attribute__((section("maps"), used)) tcpmon_map = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(struct event),
};
#endif

#define BPF_F_INDEX_MASK		0xffffffffULL
#define BPF_F_CURRENT_CPU		BPF_F_INDEX_MASK

#ifdef BTF
struct {
	unsigned int (*type)[BPF_MAP_TYPE_PERCPU_ARRAY];
	unsigned int (*key_size)[sizeof(__u32)];
	unsigned int (*value_size)[sizeof(struct msg_ipv4_tcp_connect)];
	unsigned int (*max_entries)[1];
} connect_map_store __attribute__((section((".maps")), used));
#else
struct bpf_map_def __attribute__((section("maps"), used)) connect_map_store = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct msg_ipv4_tcp_connect),
	.max_entries = 1,
};
#endif

char _license[] __attribute__((section(("license")), used)) = "GPL";

__attribute__((section(("kprobe/tcp_connect")), used))
int event_ipv4_connect(struct pt_regs *ctx)
{
	struct msg_ipv4_tcp_connect *msg;
	struct sock *skp;

	struct task_struct *task;
	struct nsproxy *nsproxy;
	struct css_set *cgroups;
	struct cgroup *cgrp;
	struct net *net_ns;
	struct kernfs_node *kn;
	struct cgroup_subsys_state *subsys;
	struct event_execve *execve = 0;

	char *addr;

	__u64 tgid;
	const char *name;
	__u32 pid;
	int i;

	__u32 zero = 0;

	msg = map_lookup_elem(&connect_map_store, &zero);
	if (!msg)
		return 0;

	msg->common.op = MSG_OP_IPV4_TCPCONNECT;

       	tgid = get_current_pid_tgid();
	msg->pid.pid = tgid >> 32;
	msg->pid.uid = get_current_uid_gid();

	skp = (void *)((ctx)->di);

	probe_read(&msg->tuple.proto, sizeof(msg->tuple.proto), &(skp->__sk_common.skc_family));
	probe_read(&msg->tuple.saddr, sizeof(msg->tuple.saddr), &(skp->__sk_common.skc_rcv_saddr));
	probe_read(&msg->tuple.daddr, sizeof(msg->tuple.daddr), &(skp->__sk_common.skc_daddr));
	probe_read(&msg->tuple.dport, sizeof(msg->tuple.dport), &(skp->__sk_common.skc_dport));
	probe_read(&msg->tuple.sport, sizeof(msg->tuple.sport), &(skp->__sk_common.skc_num));

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
#if 0
				probe_read(&msg->kube.cid, sizeof(msg.kube.cid), &(cgrp->id)); 
#endif
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
							       DOCKER_ID_LENGTH - 1,
							       name);
				}
			}
		}
	}
 
	pid = msg->pid.pid;
#pragma unroll
	for (i = 0; i < 4; i++) {
		execve = map_lookup_elem(&execve_map, &pid);
		if (execve) {
			memcpy(msg->pid.filename, execve->filename, sizeof(msg->pid.filename));
			memcpy(msg->pid.args, execve->args, sizeof(char) * MAXARGS * ARGSIZE);
		}

		/* The strange if (!!) { ... break}; is here to convince the
		 * clang unroll logic to in-fact unroll this block. What is
		 * somewhat odd is converting to if (1) { ... } which should
		 * still work causes this error.
		 *  bpf_tcpmon.c:36:5: error: loop not unrolled: the optimizer \
		 *  was unable to perform the requested transformation; the    \
		 *  transformation might be disabled or specified as part of   \
		 *  an unsupported transformation ordering
		 */
		if (!execve || !msg->pid.parent) {
#ifdef PARENT_OFFSET
			addr = (void *)task;
			addr += PARENT_OFFSET;
#else
			addr = (void *)&(task->parent);
#endif
			probe_read(&task, sizeof(task), addr);
			if (!task)
				break;
#ifdef PARENT_PID_OFFSET
			addr = (void *)(task);
			addr += PARENT_PID_OFFSET;
#else
			addr = (void *)&(task->pid);
#endif
			probe_read(&pid, sizeof(pid), addr);
			if (!msg->pid.parent) {
				msg->pid.parent = pid;
			}
			if (execve)
				break;
		}
	}

	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, msg, sizeof(*msg));
	return 0;
}
