//#include <string.h>
//#include <linux/bpf.h>
//#include <linux/ipv6.h>
//#include <linux/version.h>
//#include <sys/socket.h>
//#include "rover_kernel.h"
#include "vmlinux.h"
#include "api.h"
#include "hubble_msg.h"
//#include "bpf.h"
/*
 * TIMESTAMP PID UID TUPLE COMM NETNS DOCKER_ID
 */
struct {
	unsigned int (*type)[BPF_MAP_TYPE_PERF_EVENT_ARRAY];
	unsigned int (*key_size)[sizeof(int)];
	unsigned int (*value_size)[sizeof(struct event)];
} tcpmon_map __attribute__((section((".maps")), used));

#define bpf_printk(fmt, ...)				\
({							\
	char ____fmt[] = fmt;				\
	trace_printk(____fmt, sizeof(____fmt),	\
			 ##__VA_ARGS__);		\
})

#define BPF_F_INDEX_MASK		0xffffffffULL
#define BPF_F_CURRENT_CPU		BPF_F_INDEX_MASK

#define _(P) ({typeof(P) val = 0; probe_read(&val, sizeof(val), &P); val;})
char _license[] __attribute__((section(("license")), used)) = "GPL";
int  _version __attribute__((section(("version")), used)) = 1;

__attribute__((section(("kprobe/tcp_connect")), used))
int event_ipv4_connect(struct pt_regs *ctx)
{
	struct msg_ipv4_tuple tuple = {0};
	struct msg_ipv4_tcp_connect msg = {0};
	struct msg_common common = {0};
	struct msg_pid pid = {0};
	struct msg_k8s kube = {0};
	struct sock *skp;

	struct mnt_namespace *mnt_ns;
	struct task_struct *task;
	struct nsproxy *nsproxy;
	struct css_set *cgroups;
	struct cgroup *cgrp;
	struct kernfs_node *krn;
	struct sock_common *skc;
	struct net *net_ns;
	struct kernfs_node *kn;
	struct cgroup_subsys_state *subsys;

	__u64 tgid;
	const char *name;


	common.timestamp = ktime_get_ns() / 1000;
	common.op = MSG_OP_IPV4_TCPCONNECT;

       	tgid = get_current_pid_tgid();
	pid.pid = tgid >> 32;
	pid.uid = get_current_uid_gid();

	skp = (void *)((ctx)->di);

	probe_read(&tuple.saddr, sizeof(tuple.saddr), &(skp->__sk_common.skc_rcv_saddr));
	probe_read(&tuple.daddr, sizeof(tuple.daddr), &(skp->__sk_common.skc_daddr));
	//tuple.proto = 0;
	probe_read(&tuple.dport, sizeof(tuple.dport), &(skp->__sk_common.skc_dport));
	probe_read(&tuple.sport, sizeof(tuple.sport), &(skp->__sk_common.skc_num));

	task = (struct task_struct *)get_current_task();

	probe_read(&nsproxy, sizeof(nsproxy), &(task->nsproxy));
	if (nsproxy) {
		probe_read(&net_ns, sizeof(net_ns), &(nsproxy->net_ns));
		if (net_ns)
			probe_read(&kube.net_ns, sizeof(kube.net_ns), &(net_ns->ns.inum));
	}

	kube.cgrpid = get_current_cgroup_id();
	probe_read(&cgroups, sizeof(cgroups), &(task->cgroups));
	if (cgroups) {
		probe_read(&subsys, sizeof(subsys), &(cgroups->subsys[0]));
		if (subsys) {
			probe_read(&cgrp, sizeof(cgrp), &(subsys->cgroup));
			if (cgrp) {
				probe_read(&kube.cid, sizeof(kube.cid), &(cgrp->id)); 
				probe_read(&kn, sizeof(cgrp->kn), &(cgrp->kn));
				if (kn) {
					probe_read(&name, sizeof(name), &(kn->name));
					if (name)
						probe_read_str(kube.docker_id, DOCKER_ID_LENGTH, name);
				}
			}
		}
	}
 
	msg.common = common;
	msg.pid = pid;
	msg.kube = kube;
	msg.tuple = tuple;
              
	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
	return 0;
}
