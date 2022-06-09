#include "vmlinux.h"

#include "api.h"
#include "iso_msg_types.h"
#include "hubble_msg.h"
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
tcp_connect_event_map = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct msg_ip_event),
	.max_entries = 1,
};

__attribute__((section("kprobe/tcp_connect"), used)) int
event_tcp4_connect(struct pt_regs *ctx)
{
	struct execve_map_value *process = 0;
	struct msg_ip_event *val;
	__u32 saddr;
	__u16 sport;
	__u32 ppid = 0, pid = 0, zero = 0;
	struct sock *skp;
	bool walker = 0;
	uint64_t size;
	__u32 daddr;
	__u16 dport;

	pid = (get_current_pid_tgid() >> 32);
	process = event_find_curr(&ppid, 0, &walker);
	if (!process)
		return 0;

	val = map_lookup_elem(&tcp_connect_event_map, &zero);
	if (!val) {
		return 0;
	}

	skp = (void *)((ctx)->di);
	probe_read(&saddr, sizeof(saddr), _(&(skp->__sk_common.skc_rcv_saddr)));
	probe_read(&sport, sizeof(sport), _(&(skp->__sk_common.skc_num)));
	probe_read(&daddr, sizeof(daddr), _(&(skp->__sk_common.skc_daddr)));
	probe_read(&dport, sizeof(dport), _(&(skp->__sk_common.skc_dport)));

	*val = (struct msg_ip_event){
		.common.op = ISO_MSG_OP_TCPCONNECTRET,
		.common.ktime = ktime_get_ns(),
		.common.size = sizeof(struct msg_ip_event),
		.tuple.saddr = saddr,
		.tuple.daddr = daddr,
		.tuple.dport = dport,
		.tuple.sport = sport,
		.key.pid = process->key.pid,
		.key.ktime = process->key.ktime,
		.socket_cookie = get_cookie(skp),
		.socket_flags = 0,
		.pad = 0,
	};

	size = sizeof(struct msg_ip_event);
	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, val, size);

	/* tuple is on the stack and verifier wont use stack in call happily
	 * if its not initialized. Alternatively, without padding we are not
	 * 32-bit aligned so we really do want it there.
	 */
	{
		struct socketmap_value v = { 0 };
		struct msg_tls_ipv4 tuple;

		tuple.saddr = saddr;
		tuple.daddr = daddr;
		tuple.dport = dport;
		tuple.sport = sport;
		tuple.uid = 0;
		tuple.remaining = 0;

		v.key.pid = process->key.pid;
		v.key.ktime = process->key.ktime;
		v.socket_flags |= SOCKFLAGS_TYPE_CONNECT;
		v.sent = 0;
		v.received = 0;

		if (is_tuple_local(&tuple))
			tuple.uid = sock_netns(skp);

		add_socketmap(&tuple, &v);
	}
	return 1;
}
