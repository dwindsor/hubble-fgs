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
#include "../parsers/tls/tls_map.h"
#include "../parsers/bottle.h"
#include "../parsers/http/http.h"
#include "bpf_events.h"
#include "cookie.h"
#include "bpf_network_helpers.h"
#include "netns.h"

char _license[] __attribute__((section(("license")), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

struct bpf_map_def __attribute__((section("maps"), used))
tcp_close_event_map = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct msg_ipv4_event),
	.max_entries = 1,
};

__attribute__((section(("kprobe/tcp_set_state")), used)) int
event_tcp4_close(struct pt_regs *ctx)
{
	struct msg_ipv4_event *val;
	struct socketmap_value *process;
	struct msg_tls_ipv4 tuple;
	struct net *netns;
	struct sock *skp;
	size_t size;
	int state;
	u32 zero = 0;

	state = ctx->si;
	if (state != TCP_CLOSE && state != TCP_ESTABLISHED)
		return 0;

	skp = (void *)((ctx)->di);

	probe_read(&tuple.saddr, sizeof(tuple.saddr),
		   _(&(skp->__sk_common.skc_rcv_saddr)));
	probe_read(&tuple.sport, sizeof(tuple.sport),
		   _(&(skp->__sk_common.skc_num)));
	probe_read(&tuple.daddr, sizeof(tuple.daddr),
		   _(&(skp->__sk_common.skc_daddr)));
	probe_read(&tuple.dport, sizeof(tuple.dport),
		   _(&(skp->__sk_common.skc_dport)));

	tuple.remaining = 0;
	tuple.uid = 0;

	if (is_tuple_local(&tuple))
		tuple.uid = sock_netns(skp);

	val = map_lookup_elem(&tcp_close_event_map, &zero);
	if (!val) {
		return 0;
	}

	*val = (struct msg_ipv4_event){
		.common.size = sizeof(struct msg_ipv4_event),
		.common.ktime = ktime_get_ns(),

		.tuple.saddr = tuple.saddr,
		.tuple.daddr = tuple.daddr,
		.tuple.dport = tuple.dport,
		.tuple.sport = tuple.sport,
		.socket_cookie = get_cookie(skp),
		.socket_flags = 0,
		.pad = 0,
	};

	if (state == TCP_CLOSE) {
		process = lookup_socketmap(&tuple);
		if (process) {
			val->common.op = MSG_OP_IPV4_TCPCLOSE;
			val->key.pid = process->key.pid;
			val->key.ktime = process->key.ktime;
			val->socket_flags = process->socket_flags;

			probe_read(&netns, sizeof(netns),
				   _(&skp->__sk_common.skc_net));
			get_socket_stats(skp, netns, process->zero_window,
					 &val->stats);

			size = sizeof(struct msg_ipv4_event);
			perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU,
					  val, size);
		}
	} else { // state == TCP_ESTABLISHED
		__u32 daddr = tuple.daddr;
		__u32 saddr = tuple.saddr;
		__u16 dport = tuple.dport;

		tuple.daddr = 0;
		tuple.dport = 0;

		/* First we search the tuple with saddr set then check for
		 * any listening sockets with saddr 0.0.0.0. Listen sockets
		 * always have a uid so only search key space with non-zero
		 * uid.
		 */
		process = lookup_socketmap(&tuple);
		if (!process) {
			tuple.saddr = 0;
			process = lookup_socketmap(&tuple);
		}
		if (process) {
			struct socketmap_value copy = *process;

			val->common.op = MSG_OP_IPV4_TCPACCEPT;
			val->key.pid = copy.key.pid;
			val->key.ktime = copy.key.ktime;
			size = sizeof(struct msg_ipv4_event);
			perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU,
					  val, size);
			tuple.daddr = daddr;
			tuple.dport = dport;
			tuple.saddr = saddr;
			copy.socket_flags &=
				~SOCKFLAGS_TYPE_MASK; // clear all types but keep the rest
			copy.socket_flags |= SOCKFLAGS_TYPE_ACCEPT;
			if (!is_tuple_local(&tuple))
				tuple.uid = 0;
			add_socketmap(&tuple, &copy);
		}
	}

	if (state == TCP_CLOSE) {
		if (!is_tuple_local(&tuple))
			tuple.uid = 0;
		del_socketmap(&tuple);

		map_delete_elem(&tls_map, &tuple);
		map_delete_elem(&http_map, &tuple);
		tuple.remaining = 1;
		map_delete_elem(&http_map, &tuple);
		bottle_drop(&tuple);
	}
	return 1;
}
