#include "vmlinux.h"

#include "api.h"
#include "hubble_msg.h"
#include "bpf_events.h"
#include "cookie.h"
#include "bpf_network_helpers.h"
#include "bpf_process_network_watermarks.h"
#include "netns.h"
#include "tlsmsg.h"

struct tcp_send_check_sample_cfg {
	__u64 ktime;
	__u64 watermarksEnable;
	__u64 watermarksAvgWindowSize;
	__u64 watermarksWindowSizeNs;
	__u64 watermarksBurstTriggerMult;
	__u64 watermarksDipTriggerMult;
	__u32 bucket00;
	__u32 bucket01;
	__u32 bucket10;
	__u32 bucket25;
	__u32 bucket50;
	__u32 bucket75;
	__u32 bucket90;
	__u32 bucket99;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct tcp_send_check_sample_cfg);
	__uint(max_entries, 1);
} tcp_send_check_sampler SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct msg_ip_event);
	__uint(max_entries, 1);
} tcp_send_check_event_map SEC(".maps");

static inline __attribute__((always_inline)) int
__event_tcp_send_check(struct pt_regs *ctx, struct sock *skp, bool ipv6)
{
	struct socketmap_value *process;
	struct tcp_sock *tcp;
	struct net *netns;
	int zero = 0;
	u64 cookie;
	u8 state;

	tcp = (struct tcp_sock *)skp;
	/* In TCP we use the struct sock address as the socket cookie.
	 */
	cookie = (u64)skp;

	/* Collect socket tuple and process info, updating state so close
	 * event will read zero window stats. If sampling we push event
	 * to user space.
	 */

	process = lookup_socketmap(&cookie);
	if (process) {
		struct tcp_send_check_sample_cfg *cfg;
		u64 current_time_ns = ktime_get_ns();
		struct msg_ip_event *val;
		__u32 rcv_wnd;
		size_t size;

		/* Get the current socket TCP state. */
		probe_read(&state, sizeof(state),
			   _((const void *)&(skp->__sk_common.skc_state)));

		/* If we're in FIN_WAIT2, then the packet we are sending *must*
		 * (according to the TCP finite state machine, caveat emptor) be
		 * ACKing a FIN. Assuming a relatively standard TCP stack - one
		 * where FIN packets do not have a payload (i.e. payloads are
		 * sent, and then afterwards a FIN is sent) - this means that a
		 * FIN packet with 0 payload was received, and this would have
		 * incremented our receive sequence number by 1. As we use this
		 * value as our bytes_received count, we need to reduce it by 1
		 * when we report the count, which we do in the tcp_close program.
		 * We therefore set a flag on the socket to indicate this and do
		 * not process further in this program.
		 */
		if (state == TCP_FIN_WAIT2) {
			process->ack_finack = 1;
			return 0;
		}

		/* Check if this socket is established. If it is in the handshake
		 * then there will be no data to account; if it is closing, then
		 * we will account for the data when the socket actually closes.
		 * This will avoid the receive bytes off-by-one that happens when
		 * a FIN/ACK is received, and will save processing when
		 * unnecessary.
		 */
		if (state != TCP_ESTABLISHED)
			return 0;

		/* Check for zero window event. On zero window events we want to
		 * do some extra accounting to report these events to user space.
		 */
		probe_read(&rcv_wnd, sizeof(__u32), _(&(tcp->rcv_wnd)));
		if (!rcv_wnd)
			process->zero_window++;

		cfg = (struct tcp_send_check_sample_cfg *)map_lookup_elem(
			&tcp_send_check_sampler, &zero);
		if (!cfg)
			return 0;
		if (!process->last_time) {
			process->last_time = current_time_ns;
			goto out;
		} else if (process->last_time + cfg->ktime > current_time_ns) {
			goto out;
		}

		process->last_time = current_time_ns;
		val = (struct msg_ip_event *)map_lookup_elem(
			&tcp_send_check_event_map, &zero);
		if (!val)
			goto out;

		*val = (struct msg_ip_event){
			.common.op = ISO_MSG_OP_TCPSTATS,
			.common.size = sizeof(struct msg_ip_event),
			.common.ktime = current_time_ns,

			.key.pid = process->key.pid,
			.key.ktime = process->key.ktime,

			.socket_cookie = cookie,
			.socket_flags = 0,
			.pad = 0,
			.duration = 0,
		};

		probe_read(&val->tuple.sport, sizeof(val->tuple.sport),
			   _(&(skp->__sk_common.skc_num)));
		probe_read(&val->tuple.dport, sizeof(val->tuple.dport),
			   _(&(skp->__sk_common.skc_dport)));

		if (!ipv6) {
			val->tuple.ipv6 = false;
			probe_read(&val->tuple.saddr[0], sizeof(__u32),
				   _(&(skp->__sk_common.skc_rcv_saddr)));
			val->tuple.saddr[1] = 0;
			probe_read(&val->tuple.daddr[0], sizeof(__u32),
				   _(&(skp->__sk_common.skc_daddr)));
			val->tuple.daddr[1] = 0;
		} else {
			val->tuple.ipv6 = true;
			probe_read(&val->tuple.saddr[0],
				   sizeof(val->tuple.saddr),
				   _(&(skp->__sk_common.skc_v6_rcv_saddr)));
			probe_read(&val->tuple.daddr[0],
				   sizeof(val->tuple.daddr),
				   _(&(skp->__sk_common.skc_v6_daddr)));
		}

		probe_read(&netns, sizeof(netns), _(&skp->__sk_common.skc_net));
		get_socket_stats(skp, netns, process, &val->stats);
		size = sizeof(struct msg_ip_event);
		perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, val,
				  size);
	out:
		if (cfg->watermarksEnable) {
			if (process->key.pid != 0) {
				struct process_network_watermarks_config c = {
					.avg_window_size_ms =
						cfg->watermarksAvgWindowSize,
					.window_size =
						cfg->watermarksWindowSizeNs,
					.burst_trigger_mult =
						cfg->watermarksBurstTriggerMult,
					.dip_trigger_mult =
						cfg->watermarksDipTriggerMult,
				};
				u64 tcp_bytes_sent, tcp_bytes_received;
				probe_read(&tcp_bytes_sent, sizeof(__u64),
					   _(&(tcp->bytes_sent)));
				probe_read(&tcp_bytes_received, sizeof(__u64),
					   _(&(tcp->bytes_received)));
				if (tcp_bytes_sent > process->sent) {
					process_network_watermarks(
						ctx, process, IPPROTO_TCP,
						WATERMARKS_KEY_SEND_EGRESS,
						tcp_bytes_sent - process->sent,
						&c);
					process->sent = tcp_bytes_sent;
				}
				if (tcp_bytes_received > process->received) {
					process_network_watermarks(
						ctx, process, IPPROTO_TCP,
						WATERMARKS_KEY_SEND_INGRESS,
						tcp_bytes_received -
							process->received,
						&c);
					process->received = tcp_bytes_received;
				}
			}
		}
	}
	return 1;
}
