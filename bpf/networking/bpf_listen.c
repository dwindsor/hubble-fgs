#include "vmlinux.h"

#include "api.h"
#include "iso_msg_types.h"
#include "bpf_events.h"
#include "cookie.h"
#include "netns.h"
#include "tlsmsg.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

struct bpf_map_def __attribute__((section("maps"), used))
tcp_listen_event_map = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct msg_ip_event),
	.max_entries = 1,
};

__attribute__((section("kprobe/inet_hash"), used)) int
event_sys_listen(struct pt_regs *ctx)
{
	struct msg_ip_event *val;
	struct execve_map_value *process = 0;
	__u32 saddr;
	__u16 sport;
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
	probe_read(&saddr, sizeof(saddr), _(&(skp->__sk_common.skc_rcv_saddr)));
	probe_read(&sport, sizeof(sport), _(&(skp->__sk_common.skc_num)));

	*val = (struct msg_ip_event){
		.tuple.ipv6 = false,
		.tuple.saddr[0] = saddr,
		.tuple.saddr[1] = 0,
		.tuple.sport = sport,
		.common.op = ISO_MSG_OP_LISTEN,
		.common.ktime = ktime_get_ns(),
		.common.size = sizeof(struct msg_ip_event),
		.key.pid = pid,
		.key.ktime = process->key.ktime,
		.socket_cookie = get_cookie(skp),
		.socket_flags = 0,
		.pad = 0,
	};

	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, val,
			  sizeof(struct msg_ip_event));

	{
		struct socketmap_value v = { 0 };
		struct msg_execve_key ev = { 0 };
		struct msg_tls_ipv4 tuple;

		tuple.saddr = saddr;
		tuple.daddr = 0;
		tuple.dport = 0;
		tuple.sport = sport;
		tuple.uid = 0;
		tuple.remaining = 0;

		if (is_tuple_local(&tuple))
			tuple.uid = sock_netns(skp);

		ev.pid = process->key.pid;
		ev.ktime = process->key.ktime;
		v.key = ev;
		v.zero_window = 0;
		v.socket_flags |= SOCKFLAGS_TYPE_LISTEN;
		v.sent = 0;
		v.received = 0;

		add_socketmap(&tuple, &v);
	}

	return 0;
}
