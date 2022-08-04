#include "vmlinux.h"

#include "api.h"
#include "iso_msg_types.h"
#include "hubble_msg.h"
#include "bpf_events.h"
#include "cookie.h"
#include "netns.h"
#include "tlsmsg.h"
#include "../parsers/tls/tls_map.h"
#include "bpf_fd_to_sk.h"

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
event_tcp_connect(struct pt_regs *ctx)
{
	struct execve_map_value *process = 0;
	struct msg_ip_event *val;
	__u32 ppid = 0, zero = 0;
	struct sock *skp;
	bool walker = 0;
	u16 family;
	uint64_t size;
	u64 cookie;

	process = event_find_curr(&ppid, &walker);
	if (!process)
		return 0;

	val = (struct msg_ip_event *)map_lookup_elem(&tcp_connect_event_map,
						     &zero);
	if (!val) {
		return 0;
	}

	skp = (struct sock *)((ctx)->di);
	/* In TCP we use the struct sock address as the socket cookie.
	 */
	cookie = (u64)skp;

	*val = (struct msg_ip_event){
		.common.op = ISO_MSG_OP_TCPCONNECTRET,
		.common.ktime = ktime_get_ns(),
		.common.size = sizeof(struct msg_ip_event),
		.key.pid = process->key.pid,
		.key.ktime = process->key.ktime,
		.socket_cookie = cookie,
		.socket_flags = 0,
		.pad = 0,
	};

	probe_read(&val->tuple.sport, sizeof(val->tuple.sport),
		   _(&(skp->__sk_common.skc_num)));
	probe_read(&val->tuple.dport, sizeof(val->tuple.dport),
		   _(&(skp->__sk_common.skc_dport)));

	probe_read(&family, sizeof(family), _(&(skp->__sk_common.skc_family)));

	if (family != AF_INET6) {
		val->tuple.ipv6 = false;
		probe_read(&val->tuple.saddr[0], sizeof(__u32),
			   _(&(skp->__sk_common.skc_rcv_saddr)));
		val->tuple.saddr[1] = 0;
		probe_read(&val->tuple.daddr[0], sizeof(__u32),
			   _(&(skp->__sk_common.skc_daddr)));
		val->tuple.daddr[1] = 0;
	} else {
		val->tuple.ipv6 = true;
		probe_read(&val->tuple.saddr[0], sizeof(val->tuple.saddr),
			   _(&(skp->__sk_common.skc_v6_rcv_saddr)));
		probe_read(&val->tuple.daddr[0], sizeof(val->tuple.daddr),
			   _(&(skp->__sk_common.skc_v6_daddr)));
	}

	size = sizeof(struct msg_ip_event);
	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, val, size);

	struct socketmap_value v = { 0 };
	v.key.pid = process->key.pid;
	v.key.ktime = process->key.ktime;
	v.socket_flags |= SOCKFLAGS_TYPE_CONNECT;
	v.sent = 0;
	v.received = 0;

	if (family != AF_INET6) {
		/* tuple is on the stack and verifier wont use stack in call happily
		* if its not initialized. Alternatively, without padding we are not
		* 32-bit aligned so we really do want it there.
		*/
		struct msg_tls_ipv4 tuple;

		tuple.saddr = val->tuple.saddr[0];
		tuple.daddr = val->tuple.daddr[0];
		tuple.dport = val->tuple.dport;
		tuple.sport = val->tuple.sport;
		tuple.uid = 0;
		tuple.remaining = 0;

		if (is_tuple_local(&tuple))
			tuple.uid = sock_netns(skp);

		add_socketmap(&cookie, &tuple, &v);
	} else {
		add_socketmap(&cookie, 0, &v);
	}
	return 1;
}
