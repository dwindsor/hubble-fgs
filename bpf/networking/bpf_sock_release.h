#include "vmlinux.h"

#include "api.h"
#include "hubble_msg.h"
#include "bpf_events.h"
#include "bpf_udp.h"
#include "cookie.h"
#include "bpf_fd_lookup.h"
#include "bpf_tracing.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct msg_ip_event);
	__uint(max_entries, 1);
} udp_close_event_map SEC(".maps");

static inline __attribute__((always_inline)) int
__sk_free(struct pt_regs *ctx, bool lazy)
{
	struct sock *sk = (struct sock *)PT_REGS_PARM1_CORE(ctx);
	__u64 cookie;
	u16 protocol;
	int zero = 0;
	struct fd_lookup_config *config;
	struct socketmap_value *process;
	struct msg_ip_event *event;
	size_t size;

	if (!sk) {
		emit_ip_error_event(ctx, 0, 0, false,
				    IP_ERROR_SOCK_RELEASE_NO_SOCK);
		return 0;
	}

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

	/* Look up socket */
	process = lookup_socketmap(&cookie);
	if (!process) {
		return 0;
	}

	if (protocol != IPPROTO_UDP) {
		/* We store sockets regardless of protocol in sk_alloc (because a socket
		 * might not have a protocol assigned at time of creation) so let's remove
		 * them here, seeing as they're closed. */
		del_socketmap(&cookie, sk, 0, lazy);
		return 0;
	}

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
	/* Fill in the current time as a place-holder for the duration. We will calculate
	 * the actual duration when we walk all the pseudo-sockets associated with this
	 * socket. */
	event->duration = ktime_get_ns();

	event->tuple.ipv6 = 0;
	event->tuple.saddr[0] = 0;
	event->tuple.saddr[1] = 0;
	event->tuple.daddr[0] = 0;
	event->tuple.daddr[1] = 0;
	event->tuple.sport = 0;
	event->tuple.dport = 0;

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

	size = sizeof(struct msg_ip_event);
	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, event, size);

	del_socketmap(&cookie, sk, 0, lazy);
	return 1;
}
