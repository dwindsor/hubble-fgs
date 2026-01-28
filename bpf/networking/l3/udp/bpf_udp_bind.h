// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef __BPF_UDP_BIND_H_
#define __BPF_UDP_BIND_H_

#include "vmlinux.h"

#include "api.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "bpf_cookie.h"
#include "bpf_tracing.h"
#include "config.h"
#include "bpf_event_map.h"

static inline __attribute__((always_inline)) int
__udp_bind_sock(void *ctx, __u64 cookie, bool ipv6)
{
	struct udp_sensor_config *config;
	struct socketmap_value *process;
	struct msg_ip_event *event;
	struct cfg_value *l3cfg;
	struct sock *sk;
	u16 protocol;
	int zero = 0;
	size_t size;

	l3cfg = getl3cfg();
	if (!l3cfg)
		return 0;
	config = &l3cfg->udp;
	if (config->disable_listen_events)
		return 0;

	sk = (struct sock *)cookie;
	probe_read_kernel(&protocol, sizeof(protocol), _(&(sk->sk_protocol)));
	// Check if sk_protocol is a u8 within a u32 or is a u16 in its own right.
	// See bpf_fd_to_sk.h for info.
	if (bpf_core_field_size(sk->sk_protocol) == sizeof(u32)) {
		protocol >>= 8;
	}
	if (protocol != IPPROTO_UDP)
		return 0;

	event = (struct msg_ip_event *)map_lookup_elem(&tg_h_event, &zero);
	if (!event)
		return 0;

	process = lookup_socketmap(&cookie);
	if (!process)
		return 0;

	*event = (struct msg_ip_event){
		.common.size = sizeof(struct msg_ip_event),
		.common.ktime = tg_get_ktime(),
		.common.op = ISO_MSG_OP_UDPLISTEN,
		.key.pid = process->key.pid,
		.key.ktime = process->key.ktime,

		.socket_cookie = cookie,
	};

	if (!ipv6) {
		event->tuple.ipv6 = 0;
		probe_read_kernel(&event->tuple.saddr[0], sizeof(__u32),
				  _(&(sk->__sk_common.skc_rcv_saddr)));
		event->tuple.saddr[1] = 0;
	} else {
		event->tuple.ipv6 = 1;
		probe_read_kernel(&event->tuple.saddr[0], sizeof(event->tuple.saddr),
				  _(&(sk->__sk_common.skc_v6_rcv_saddr)));
	}

	probe_read_kernel(&event->tuple.sport, sizeof(event->tuple.sport),
			  _(&(sk->__sk_common.skc_num)));
	event->tuple.proto = IPPROTO_UDP;
	event->tuple.conn_id = 0;

	event->version = process->version;

	size = sizeof(struct msg_ip_event);
	perf_event_output_metric(ctx, ISO_MSG_OP_UDPLISTEN, &tcpmon_map, BPF_F_CURRENT_CPU, event, size);
	return 1;
}

#endif
