#include "vmlinux.h"

#include "api.h"
#include "bpf_event.h"
#include "../parsers/tls/tls_map.h"
#include "bpf_task.h"
#include "cookie.h"
#include "bpf_network_helpers.h"
#include "bpf_fd_to_sk.h"
#include "bpf_tcp_send_check.h"
#include "bpf_tracing.h"
#include "../parsers/http/http.h"
#include "../parsers/bottle.h"
#include "bpf_network_event_config.h"

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
tg_event_tcp_close(struct pt_regs *ctx)
{
	struct tcp_event_disable_config *event_cfg;
	struct socketmap_value *process;
	struct msg_ip_event *val;
	unsigned char old_state;
	struct sock *skp;
	u32 zero = 0;
	size_t size;
	int state;
	u64 cookie;

	state = PT_REGS_PARM2(ctx);
	if (state != TCP_CLOSE)
		return 0;

	skp = (struct sock *)PT_REGS_PARM1(ctx);
	/* In TCP we use the struct sock address as the socket cookie.
	 */
	cookie = (u64)skp;

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

	process = lookup_socketmap(&cookie);
	if (!process)
		return 0;

	val->common.op = ISO_MSG_OP_TCPCLOSE;
	val->key.pid = process->key.pid;
	val->key.ktime = process->key.ktime;
	val->duration = ktime_get_ns() - process->create_time;
	val->socket_flags = process->socket_flags;
	val->tuple = process->tuple;

	get_socket_stats(skp, process, &val->stats);

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

	event_cfg = (struct tcp_event_disable_config *)map_lookup_elem(
		&tg_event_disable_config, &zero);
	if (!event_cfg)
		return 0;

	size = sizeof(struct msg_ip_event);
	if (!event_cfg->disableClose) {
		perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, val,
				  size);
	}

	if (!process->tuple.ipv6) {
		del_socketmap(&cookie);

		del_tlsmap(&cookie);
		map_delete_elem(&tg_http_map, &cookie);
		map_delete_elem(&tg_http_map, &cookie);
		bottle_drop(&cookie);
	} else {
		del_socketmap(&cookie);
	}

	return 1;
}
