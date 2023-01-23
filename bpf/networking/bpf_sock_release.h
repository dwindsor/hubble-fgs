#include "vmlinux.h"

#include "api.h"
#include "hubble_msg.h"
#include "bpf_events.h"
#include "bpf_udp.h"
#include "cookie.h"
#include "bpf_fd_lookup.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct msg_ip_event);
	__uint(max_entries, 1);
} udp_close_event_map SEC(".maps");

static inline __attribute__((always_inline)) int
__sock_release(struct pt_regs *ctx, bool lazy)
{
	struct socket *socket = (struct socket *)((ctx)->di);
	struct sock *sk;
	__u64 cookie;
	u16 protocol;
	int zero = 0;
	struct fd_lookup_config *config;
	struct socketmap_value *process;
	struct udp_info_value *value;
	struct msg_ip_event *event;
	u16 family;
	size_t size;

	probe_read(&sk, sizeof(sk), _(&(socket->sk)));
	write_cookie_from_sk(&cookie, sk, lazy);
	if (!cookie) {
		emit_ip_error_event(ctx, 0, 0, false,
				    IP_ERROR_SOCK_RELEASE_NO_COOKIE);
		return 0;
	}

	/* We only want to release sockets for UDP as TCP is handled via
	 * calls to tcp_set_state.
	 */
	config = (struct fd_lookup_config *)map_lookup_elem(
		&fd_lookup_config_map, &zero);
	if (!config)
		return 0;
	probe_read(&protocol, sizeof(protocol), _(&(sk->sk_protocol)));
	if (config->proto_shift) {
		protocol >>= 8;
	}

	if (protocol != IPPROTO_UDP) {
		return 0;
	}

	/* Look up socket */
	process = lookup_socketmap(&cookie);
	if (!process) {
		return 0;
	}

	/* Look up socket info */
	value = map_lookup_elem(&udp_map, &cookie);

	event = (struct msg_ip_event *)map_lookup_elem(&udp_close_event_map, &zero);
	if (!event) {
		return 0;
	}

	*event = (struct msg_ip_event){
		.common.size = sizeof(struct msg_ip_event),
		.common.ktime = ktime_get_ns(),
		.common.op = ISO_MSG_OP_UDPCLOSE,
		.key.pid = process->key.pid,
		.key.ktime = process->key.ktime,

		.socket_cookie = cookie,
		.socket_flags = process->socket_flags,
		.pad = 0,
	};
	event->duration = event->common.ktime - process->create_time;

	if (value) {
		event->tuple.saddr[0] = value->saddr[0];
		event->tuple.saddr[1] = value->saddr[1];
		event->tuple.daddr[0] = value->daddr[0];
		event->tuple.daddr[1] = value->daddr[1];
		event->tuple.ipv6 = value->ipv6;
		event->tuple.sport = value->sport;
		event->tuple.dport = value->dport;

		event->stats.ktime = value->ktime;
		event->stats.bytes_sent = value->tx_bytes;
		event->stats.bytes_received = value->rx_bytes;
		event->stats.segs_out = value->segs_out;
		event->stats.segs_in = value->segs_in;
		event->stats.bytes_submitted = value->submitted_bytes;
		event->stats.bytes_consumed = value->consumed_bytes;
		event->stats.segs_submitted = value->submitted_segs;
		event->stats.segs_consumed = value->consumed_segs;
		event->stats.sk_drops = value->sk_drops;
		event->stats.skb_consume_misses = value->skb_consume_misses;

		/* Delete the UDP info as this socket is closing */
		map_delete_elem(&udp_map, &cookie);
	} else {
		probe_read(&family, sizeof(family), _(&(sk->__sk_common.skc_family)));
		if (family != AF_INET6) {
			event->tuple.ipv6 = false;
			probe_read(&event->tuple.saddr[0], sizeof(u32), _(&(sk->__sk_common.skc_rcv_saddr)));
			event->tuple.saddr[1] = 0;
			probe_read(&event->tuple.daddr[0], sizeof(u32), _(&(sk->__sk_common.skc_daddr)));
			event->tuple.daddr[1] = 0;
		} else {
			event->tuple.ipv6 = true;
			probe_read(&event->tuple.saddr[0], sizeof(event->tuple.saddr), _(&(sk->__sk_common.skc_v6_rcv_saddr)));
			probe_read(&event->tuple.daddr[0], sizeof(event->tuple.daddr), _(&(sk->__sk_common.skc_v6_daddr)));
		}
		probe_read(&event->tuple.sport, sizeof(event->tuple.sport), _(&(sk->__sk_common.skc_num)));
		probe_read(&event->tuple.dport, sizeof(event->tuple.dport), _(&(sk->__sk_common.skc_dport)));

		event->stats.ktime = 0;
		event->stats.bytes_sent = 0;
		event->stats.bytes_received = 0;
		event->stats.segs_out = 0;
		event->stats.segs_in = 0;
		event->stats.bytes_submitted = 0;
		event->stats.bytes_consumed = 0;
		event->stats.segs_submitted = 0;
		event->stats.segs_consumed = 0;
		event->stats.sk_drops = 0;
		event->stats.skb_consume_misses = 0;
	}

	size = sizeof(struct msg_ip_event);
	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, event, size);

	del_socketmap(&cookie, sk, 0, lazy);
	return 1;
}
