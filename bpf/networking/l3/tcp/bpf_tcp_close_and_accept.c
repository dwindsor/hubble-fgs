// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#include "vmlinux.h"

#include "api.h"
#include "bpf_event.h"
#include "parsers/tls/tls_map.h"
#include "bpf_task.h"
#include "bpf_cookie.h"
#include "bpf_network_helpers.h"
#include "lib/netns.h"
#include "bpf_fd_to_sk.h"
#include "bpf_tcp_send_check.h"
#include "bpf_tracing.h"
#include "parsers/http/http.h"
#include "parsers/bottle.h"
#include "bpf_tcp_network_event_config.h"
#include "bpf_tcp_accept.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct msg_ip_with_stats_event);
	__uint(max_entries, 1);
} tcp_close_event_map SEC(".maps");

__attribute__((section("kprobe/tcp_set_state"), used)) int
tg_event_tcp_close_and_accept(struct pt_regs *ctx)
{
	struct tcp_event_disable_config *event_cfg;
	struct msg_ip_with_stats_event *val;
	struct socketmap_value *process;
	unsigned char old_state;
	struct sock *skp;
	u32 zero = 0;
	size_t size;
	int state;
	u64 cookie;

	state = PT_REGS_PARM2(ctx);
	skp = (struct sock *)PT_REGS_PARM1(ctx);
	/* In TCP we use the struct sock address as the socket cookie.
	 */
	cookie = (u64)skp;

	/* Get the state that we are transitioning from */
	probe_read_kernel(&old_state, sizeof(old_state),
			  _((const void *)&(skp->__sk_common.skc_state)));

	if (old_state == TCP_SYN_RECV && state == TCP_ESTABLISHED)
		return __event_tcp_accept_state(ctx, skp);

	if (state != TCP_CLOSE && state != TCP_CLOSE_WAIT)
		return 0;

	process = lookup_socketmap(&cookie);
	if (!process)
		return 0;

	if (state == TCP_CLOSE_WAIT) {
		/* When a socket is closing, it may have received a FIN/ACK segment.
		* Unfortunately, a FIN/ACK increases the received sequence counter
		* by 1 (in order to maintain appropriate state). We use the received
		* sequence counter to indicate the number of bytes received, so if
		* we have received a FIN/ACK then our counter will be 1 greater than
		* it should be. Mark the socket so that stats calculations can take
		* this into account.
		*/
		process->fin_rx = 1;
		return 0;
	}

	val = (struct msg_ip_with_stats_event *)map_lookup_elem(&tcp_close_event_map,
								&zero);
	if (!val) {
		return 0;
	}

	*val = (struct msg_ip_with_stats_event){
		.common.size = sizeof(struct msg_ip_with_stats_event),
		.common.ktime = ktime_get_ns(),

		.socket_cookie = cookie,
		.socket_flags = 0,
		.version = 0,
	};

	val->common.op = ISO_MSG_OP_TCPCLOSE;
	val->key.pid = process->key.pid;
	val->key.ktime = process->key.ktime;
	val->duration = ktime_get_ns() - process->create_time;
	val->socket_flags = process->socket_flags;
	val->tuple = process->tuple;

	get_socket_stats(skp, process, &val->stats);
	val->stats.bytes_received -= process->fin_rx;

	event_cfg = (struct tcp_event_disable_config *)map_lookup_elem(
		&tg_event_disable_config, &zero);
	if (!event_cfg)
		return 0;

	size = sizeof(struct msg_ip_with_stats_event);
	if (!event_cfg->disableClose) {
		perf_event_output_metric(ctx, ISO_MSG_OP_TCPCLOSE, &tcpmon_map, BPF_F_CURRENT_CPU, val,
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
