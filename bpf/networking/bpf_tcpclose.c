#include "vmlinux.h"

#include "api.h"
#include "hubble_msg.h"
#include "../parsers/tls/tls_map.h"
#include "../parsers/bottle.h"
#include "../parsers/http/http.h"
#include "bpf_events.h"
#include "cookie.h"
#include "bpf_network_helpers.h"
#include "netns.h"
#include "bpf_fd_to_sk.h"
#include "bpf_tcp_send_check.h"
#include "bpf_tracing.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct msg_ip_event);
	__uint(max_entries, 1);
} tcp_close_event_map SEC(".maps");

__attribute__((section("kprobe/tcp_set_state"), used)) int
event_tcp_close(struct pt_regs *ctx)
{
	struct msg_ip_event *val;
	struct socketmap_value *process;
	struct msg_tls_ip tuple = { 0 };
	struct net *netns;
	struct sock *skp;
	size_t size;
	int state;
	u16 family;
	u32 zero = 0;
	u64 cookie;
	unsigned char old_state;

	state = PT_REGS_PARM2_CORE(ctx);
	if (state != TCP_CLOSE)
		return 0;

	skp = (struct sock *)PT_REGS_PARM1_CORE(ctx);
	/* In TCP we use the struct sock address as the socket cookie.
	 */
	cookie = (u64)skp;

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

	val = (struct msg_ip_event *)map_lookup_elem(&tcp_close_event_map,
						     &zero);
	if (!val) {
		return 0;
	}

	*val = (struct msg_ip_event){
		.common.size = sizeof(struct msg_ip_event),
		.common.ktime = ktime_get_ns(),

		.socket_cookie = cookie,
		.socket_flags = 0,
		.pad = 0,
	};

	probe_read(&family, sizeof(family), _(&(skp->__sk_common.skc_family)));

	probe_read(&val->tuple.sport, sizeof(val->tuple.sport),
		   _(&(skp->__sk_common.skc_num)));
	probe_read(&val->tuple.dport, sizeof(val->tuple.dport),
		   _(&(skp->__sk_common.skc_dport)));

	if (family != AF_INET6) {
		val->tuple.ipv6 = false;
		probe_read(&val->tuple.saddr[0], sizeof(u32),
			   _(&(skp->__sk_common.skc_rcv_saddr)));
		val->tuple.saddr[1] = 0;
		probe_read(&val->tuple.daddr[0], sizeof(u32),
			   _(&(skp->__sk_common.skc_daddr)));
		val->tuple.daddr[1] = 0;
	} else {
		val->tuple.ipv6 = true;
		probe_read(&val->tuple.saddr[0], sizeof(val->tuple.saddr),
			   _(&(skp->__sk_common.skc_v6_rcv_saddr)));
		probe_read(&val->tuple.daddr[0], sizeof(val->tuple.daddr),
			   _(&(skp->__sk_common.skc_v6_daddr)));
	}

	process = lookup_socketmap(&cookie);
	if (process) {
		val->common.op = ISO_MSG_OP_TCPCLOSE;
		val->key.pid = process->key.pid;
		val->key.ktime = process->key.ktime;
		val->duration = ktime_get_ns() - process->create_time;
		val->socket_flags = process->socket_flags;

		probe_read(&netns, sizeof(netns), _(&skp->__sk_common.skc_net));
		get_socket_stats(skp, netns, process, &val->stats);

		/* Get the state that we are transitioning from */
		probe_read(&old_state, sizeof(old_state),
			   _((const void *)&(skp->__sk_common.skc_state)));

		/* When a socket is closing, it may have received a FIN/ACK segment.
		 * Unfortunately, a FIN/ACK increases the received sequence counter
		 * by 1 (in order to maintain appropriate state). We use the received
		 * sequence counter to indicate the number of bytes received, so if
		 * we have received a FIN/ACK then our counter will be 1 greater than
		 * it should be.
		 * 
		 * The situations where this will be the case are any where we are
		 * transitioning from LAST_ACK to CLOSE, as all of these imply a
		 * FIN/ACK was received (as the remote end has initiated the close);
		 * and the specific case where the local end initiated the close and
		 * a FIN/ACK was ACKed, recorded in the ack_finack flag on the socket
		 * (see bpf_tcp_send_check.h for details).
		 */
		if ((old_state == TCP_LAST_ACK || process->ack_finack) &&
		    val->stats.bytes_received > 0)
			val->stats.bytes_received--;

		size = sizeof(struct msg_ip_event);
		perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, val,
				  size);
	}

	if (family != AF_INET6) {
		tuple.saddr[0] = val->tuple.saddr[0];
		tuple.daddr[0] = val->tuple.daddr[0];
		tuple.ipv6 = 0;
		tuple.sport = val->tuple.sport;
		tuple.dport = val->tuple.dport;
		tuple.remaining = 0;
		tuple.uid = 0;

		if (is_tuple_local(&tuple))
			tuple.uid = sock_netns(skp);
		del_socketmap(&cookie, skp, &tuple, false);

		del_tlsmap(&cookie);
		map_delete_elem(&http_map, &tuple);
		tuple.remaining = 1;
		map_delete_elem(&http_map, &tuple);
		bottle_drop(&cookie);
	} else {
		del_socketmap(&cookie, skp, 0, false);
	}

	return 1;
}
