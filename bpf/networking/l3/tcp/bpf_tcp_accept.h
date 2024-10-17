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
	u64 pid_tgid = get_current_pid_tgid();
	u64 accept_cookie = PT_REGS_RC(ctx);
	u64 now = ktime_get_ns();
	struct msg_ip_tuple tuple = { 0 };
	u64 cookie_version = 0;
	u64 *listen_cookie_p;
	struct sock *sk;
	u16 protocol;
	u16 family;

	/* In TCP we use the struct sock address as the socket cookie. */
	listen_cookie_p = map_lookup_elem(&tg_tcp_accept_sock_map, &pid_tgid);
	if (!listen_cookie_p) {
		emit_ip_error_event(ctx, 0, &accept_cookie, false, 0, 0, 0, IP_ERROR_TCP_ACCEPTRET_MISSING_PROCESS);
		return 0;
	}
	listen_process = lookup_socketmap(listen_cookie_p);
	listen_socket = lookup_tcpsocketmap(listen_cookie_p);
	map_delete_elem(&tg_tcp_accept_sock_map, &pid_tgid);
	if (!accept_cookie) {
		emit_ip_error_event(ctx, 0, 0, false, 0, 0, 0, IP_ERROR_TCP_ACCEPTRET_NO_COOKIE);
		return 0;
	}

	sk = (struct sock *)accept_cookie;
	probe_read_kernel(&family, sizeof(family), _(&(sk->__sk_common.skc_family)));
	if (family == AF_INET6) {
		tuple.ipv6 = 1;
		probe_read_kernel(tuple.saddr, sizeof(tuple.saddr), _(&(sk->__sk_common.skc_v6_rcv_saddr)));
		probe_read_kernel(tuple.daddr, sizeof(tuple.daddr), _(&(sk->__sk_common.skc_v6_daddr)));
	} else {
		probe_read_kernel(&tuple.saddr[0], sizeof(__u32), _(&(sk->__sk_common.skc_rcv_saddr)));
		probe_read_kernel(&tuple.daddr[0], sizeof(__u32), _(&(sk->__sk_common.skc_daddr)));
	}
	probe_read_kernel(&protocol, sizeof(protocol), _(&(sk->sk_protocol)));
	if (bpf_core_field_size(sk->sk_protocol) == sizeof(u32)) {
		protocol >>= 8;
	}
	tuple.proto = protocol;
	probe_read_kernel(&tuple.sport, sizeof(tuple.sport), _(&(sk->__sk_common.skc_num)));

	cookie_version = cookie_inc_version();
	// copy existing entries but with new version number.
	if (listen_process) {
		struct socketmap_value accept_process = *listen_process;
		accept_process.version = cookie_version;
		accept_process.create_time = now;
		add_socketmap(&accept_cookie, &accept_process, &tuple, true);
	}
	if (listen_socket) {
		struct tcpsocketmap_value accept_socket = *listen_socket;
		accept_socket.version = cookie_version;
		accept_socket.create_time = now;
		add_tcpsocketmap(&accept_cookie, &accept_socket, &tuple, true);
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
	u16 family = 0;
	u32 zero = 0;
	size_t size;

	/* In TCP we use the struct sock address as the socket cookie. */
	if (!cookie) {
		emit_ip_error_event(ctx, 0, 0, false, 0, 0, 0, IP_ERROR_TCP_ACCEPT_NO_COOKIE);
		return 0;
	}
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
		.socket_flags = SOCKFLAGS_TYPE_ACCEPT,
		.version = 0,
		.create_time = 0,
		.close_time = 0,
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
		val->version = socket->version;
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

	if (!socket) {
		emit_ip_error_event(ctx, 0, &cookie, val->tuple.ipv6, 0, 0, 0, IP_ERROR_TCP_ACCEPT_NO_SOCKET);
		return 0;
	}

	socket->create_time = val->common.ktime;
	socket->socket_flags = SOCKFLAGS_TYPE_ACCEPT;
	socket->ktime = socket->create_time;
	socket->bytes_received = 0;
	socket->bytes_sent = 0;
	socket->zero_window = 0;
	socket->fin_rx = 0;
	socket->ipv6 = (family == AF_INET6);

	add_socket_tuple_map(&val->tuple, &cookie);

	return 1;
}

#endif
