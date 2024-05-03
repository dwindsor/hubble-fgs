// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef __BPF_TCP_ACCEPT_H_
#define __BPF_TCP_ACCEPT_H_

#include "vmlinux.h"

#include "api.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "bpf_tracing.h"
#include "bpf_cookie.h"
#include "address_family.h"
#include "bpf_network_helpers.h"
#include "lib/netns.h"
#include "bpf_tcp_network_event_config.h"
#include "bpf_tcp_info.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct msg_ip_event);
	__uint(max_entries, 1);
} tcp_accept_event_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, __u64);
	__uint(max_entries, 32000);
} tg_tcp_accept_sock_map SEC(".maps");

static inline __attribute__((always_inline)) int
__event_tcp_accept(struct pt_regs *ctx)
{
	u64 pid_tgid = get_current_pid_tgid();
	u64 listen_sock = PT_REGS_PARM1(ctx);

	map_update_elem(&tg_tcp_accept_sock_map, &pid_tgid, &listen_sock, 0);
	return 1;
}

static inline __attribute__((always_inline)) int
__event_tcp_accept_ret(struct pt_regs *ctx)
{
	struct tcpsocketmap_value *listen_socket;
	struct socketmap_value *listen_process;
	u64 *listen_cookie_p;
	u64 accept_cookie = PT_REGS_RC(ctx);
	u64 pid_tgid = get_current_pid_tgid();
	u32 cookie_version = 0;

	/* In TCP we use the struct sock address as the socket cookie. */
	listen_cookie_p = map_lookup_elem(&tg_tcp_accept_sock_map, &pid_tgid);
	if (!listen_cookie_p)
		return 0;
	listen_process = lookup_socketmap(listen_cookie_p);
	listen_socket = lookup_tcpsocketmap(listen_cookie_p);
	map_delete_elem(&tg_tcp_accept_sock_map, &pid_tgid);
	if (!accept_cookie)
		return 0;

	cookie_version = cookie_inc_version();
	if (listen_process) {
		listen_process->version = cookie_version;
		add_socketmap(&accept_cookie, listen_process, true);
	}
	if (listen_socket) {
		listen_socket->version = cookie_version;
		add_tcpsocketmap(&accept_cookie, listen_socket, true);
	}
	return 1;
}

static inline __attribute__((always_inline)) int
__event_tcp_accept_state(void *ctx, struct sock *skp)
{
	struct tcp_event_disable_config *event_cfg;
	struct tcpsocketmap_value *socket;
	struct msg_ip_event *val;
	u64 cookie = (u64)skp;
	size_t size;
	u16 family = 0;
	u32 zero = 0;

	/* In TCP we use the struct sock address as the socket cookie. */
	if (!cookie)
		return 0;
	socket = lookup_tcpsocketmap(&cookie);

	val = (struct msg_ip_event *)map_lookup_elem(&tcp_accept_event_map,
						     &zero);
	if (!val)
		return 0;

	*val = (struct msg_ip_event){
		.common.size = sizeof(struct msg_ip_event),
		.common.ktime = ktime_get_ns(),
		.common.op = ISO_MSG_OP_TCPACCEPT,
		.socket_cookie = cookie,
		.socket_flags = 0,
		.version = 0,
		.duration = 0,
	};

	probe_read_kernel(&val->tuple.sport, sizeof(val->tuple.sport),
			  _(&(skp->__sk_common.skc_num)));
	probe_read_kernel(&val->tuple.dport, sizeof(val->tuple.dport),
			  _(&(skp->__sk_common.skc_dport)));
	val->tuple.dport = bpf_ntohs(val->tuple.dport);
	probe_read_kernel(&family, sizeof(family), _(&(skp->__sk_common.skc_family)));

	if (family != AF_INET6) {
		val->tuple.ipv6 = false;
		probe_read_kernel(&val->tuple.saddr[0], sizeof(u32),
				  _(&(skp->__sk_common.skc_rcv_saddr)));
		val->tuple.saddr[1] = 0;
		probe_read_kernel(&val->tuple.daddr[0], sizeof(u32),
				  _(&(skp->__sk_common.skc_daddr)));
		val->tuple.daddr[1] = 0;
	} else {
		val->tuple.ipv6 = true;
		probe_read_kernel(&val->tuple.saddr[0], sizeof(val->tuple.saddr),
				  _(&(skp->__sk_common.skc_v6_rcv_saddr)));
		probe_read_kernel(&val->tuple.daddr[0], sizeof(val->tuple.daddr),
				  _(&(skp->__sk_common.skc_v6_daddr)));
	}

	if (socket) {
		val->key.pid = socket->key.pid;
		val->key.ktime = socket->key.ktime;
	} else {
		val->key.pid = 0;
		val->key.ktime = 0;
	}

	event_cfg = (struct tcp_event_disable_config *)map_lookup_elem(
		&tg_event_disable_config, &zero);
	if (!event_cfg)
		return 0;

	size = sizeof(struct msg_ip_event);
	if (!event_cfg->disableAccept) {
		perf_event_output_metric(ctx, ISO_MSG_OP_TCPACCEPT, &tcpmon_map, BPF_F_CURRENT_CPU, val, size);
	}

	if (!socket)
		return 0;

	socket->create_time = val->common.ktime;
	socket->socket_flags = SOCKFLAGS_TYPE_ACCEPT;
	socket->last_time = 0;
	socket->received = 0;
	socket->sent = 0;
	socket->zero_window = 0;
	socket->fin_rx = 0;
	socket->tuple.saddr[0] = val->tuple.saddr[0];
	socket->tuple.saddr[1] = val->tuple.saddr[1];
	socket->tuple.daddr[0] = val->tuple.daddr[0];
	socket->tuple.daddr[1] = val->tuple.daddr[1];
	socket->tuple.ipv6 = (family == AF_INET6);
	socket->tuple.dport = val->tuple.dport;
	socket->tuple.sport = val->tuple.sport;

	add_socket_tuple_map(&cookie);

	return 1;
}

#endif
