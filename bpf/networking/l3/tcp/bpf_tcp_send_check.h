// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef __BPF_TCP_SEND_CHECK_H_
#define __BPF_TCP_SEND_CHECK_H_

#include "vmlinux.h"

#include "api.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "bpf_cookie.h"
#include "bpf_network_helpers.h"
#include "bpf_process_network_watermarks.h"
#include "lib/tlsmsg.h"
#include "bpf_tracing.h"
#include "bpf_tcp_info.h"

struct tcp_send_check_sample_cfg {
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
} tg_tcp_send_check_sampler SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct msg_ip_event);
	__uint(max_entries, 1);
} tg_tcp_send_check_event_map SEC(".maps");

static inline __attribute__((always_inline)) int
__event_tcp_send_check(struct pt_regs *ctx, struct sock *skp, bool ipv6)
{
	struct socketmap_value process = { 0 };
	struct tcp_send_check_sample_cfg *cfg;
	struct tcpsocketmap_value *socket;
	struct tcp_sock *tcp;
	__u32 rcv_wnd;
	int zero = 0;
	u64 cookie;
	u8 state;

	tcp = (struct tcp_sock *)skp;
	cookie = (u64)skp;

	/* Collect socket tuple and process info, updating state so close
	 * event will read zero window stats. If sampling we push event
	 * to user space.
	 */

	/* Get the current socket TCP state. */
	probe_read_kernel(&state, sizeof(state),
			  _((const void *)&(skp->__sk_common.skc_state)));

	socket = lookup_tcpsocketmap(&cookie);
	if (unlikely(!socket)) {
		// Don't report an error here if the TCP socket isn't yet active.
		if (tcp_active(state))
			emit_ip_error_event(ctx, 0, &cookie, ipv6, 0, 2, 0, IP_ERROR_TCP_SEND_NO_SOCKET);
		return 0;
	}

	/* We don't need to account further if the socket has already been closed. */
	if (socket->closed)
		return 0;

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
	probe_read_kernel(&rcv_wnd, sizeof(__u32), _(&(tcp->rcv_wnd)));
	if (!rcv_wnd)
		socket->stats.zero_window++;

	u64 tcp_bytes_sent, tcp_bytes_received;
	probe_read_kernel(&tcp_bytes_sent, sizeof(__u64), _(&(tcp->bytes_sent)));
	probe_read_kernel(&tcp_bytes_received, sizeof(__u64), _(&(tcp->bytes_received)));

	cfg = (struct tcp_send_check_sample_cfg *)map_lookup_elem(&tg_tcp_send_check_sampler, &zero);
	process.create_time = socket->stats.create_time;
	process.key = socket->key;
	process.protocol = socket->tuple.proto;
	process.version = socket->version;
	if (cfg && cfg->watermarksEnable && socket->key.pid != 0) {
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
		if (tcp_bytes_sent > socket->stats.bytes_sent) {
			process_network_watermarks(
				ctx, &process, IPPROTO_TCP,
				WATERMARKS_KEY_SEND_EGRESS,
				tcp_bytes_sent - socket->stats.bytes_sent,
				&c);
		}
		if (tcp_bytes_received > socket->stats.bytes_received) {
			process_network_watermarks(
				ctx, &process, IPPROTO_TCP,
				WATERMARKS_KEY_SEND_INGRESS,
				tcp_bytes_received - socket->stats.bytes_received,
				&c);
		}
	}
	tcp_socketmap_stats(skp, socket);
	return 1;
}

#endif
