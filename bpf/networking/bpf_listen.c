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
#include "cookie.h"

char _license[] __attribute__((section(("license")), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int  _version __attribute__((section(("version")), used)) = VMLINUX_KERNEL_VERSION;
#endif

struct bpf_map_def __attribute__((section("maps"), used)) tcp_listen_event_map = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct msg_ipv4_tcp_event),
	.max_entries = 1,
};

__attribute__((section(("kprobe/inet_hash")), used))
int event_sys_listen(struct pt_regs *ctx)
{
	struct msg_ipv4_tcp_event *val;
	struct execve_map_value *process = 0;
	struct msg_ipv4_tcp_key key;
	__u32 pid, ppid = 0, zero = 0;
	struct sock *skp;
	bool walker = 0;

	pid = (get_current_pid_tgid() >> 32);
	process = event_find_curr(&ppid, 0, &walker);
	if (!process)
		return 0;

	val = map_lookup_elem(&tcp_listen_event_map, &zero);
	if (!val) {
		return 0;
	}

	skp = (void *)((ctx)->di);
	probe_read(&key.saddr, sizeof(key.saddr), _(&(skp->__sk_common.skc_rcv_saddr)));
	probe_read(&key.sport, sizeof(key.sport), _(&(skp->__sk_common.skc_num)));
	key.pid = pid;
	key.pad = 0;

	*val = (struct msg_ipv4_tcp_event){
		.tuple.saddr = key.saddr,
		.tuple.sport = key.sport,
		.common.op = MSG_OP_IPV4_LISTEN,
		.common.ktime = ktime_get_ns(),
		.common.size = sizeof(struct msg_ipv4_tcp_event),
		.key.pid = pid,
		.key.ktime = process->key.ktime,
		.socket_cookie = get_cookie(skp),
	};

	map_update_elem(&ipv4_tcp_map, &key, val, 0);
	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, val, sizeof(struct msg_ipv4_tcp_event));

	{
		struct msg_execve_key v = {0};
		struct msg_tls_ipv4 tuple;
		struct net *netns;

		tuple.saddr = key.saddr;
		tuple.daddr = 0;
		tuple.dport = 0;
		tuple.sport = key.sport;
		tuple.uid = 0;
		tuple.remaining = 0;

		probe_read(&netns, sizeof(netns), _(&skp->__sk_common.skc_net));
		if (netns) {
			struct ns_common *c = _(&netns->ns);

			probe_read(&tuple.uid, sizeof(c->inum), _(&c->inum));
		}

		v.pid = process->key.pid;
		v.ktime = process->key.ktime;

		add_socketmap(&tuple, &v);
	}

	return 0;
}
