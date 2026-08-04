// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.
//
#ifndef __BPF_TCP_SECURITY_ACCEPT_H
#define __BPF_TCP_SECURITY_ACCEPT_H

#include "vmlinux.h"

#include "api.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "bpf_cookie.h"
#include "bpf_network_helpers.h"
#include "bpf_tracing.h"
#include "socktrack/bpf_sk_alloc.h"
#include "lib/address_family.h"
#include "bpf_tcp_listen.h"
#include "bpf_event_map.h"
#include "l3_config.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct socketmap_value);
	__uint(max_entries, 1);
} tg_h_tcplstn_ps SEC(".maps");

/* Theory of Operations: The kernel does not at the moment have a hook that
 * is reliable to capture both the listen sock and the new sock from the
 * accept. In the past we've glue'd the enter/exit of child sock create
 * logic in the kernel. And then another kprobe on actual accept. The result
 * was 2 kprobe + 1 kprobe_ret. This was rather slow. See Tetragon 1.14
 * versions for the details. I decided its more obvious to have two security
 * hooks instead. First we hook security_socket_accept(socket, newsocket) and
 * create a map from newsocket->(socket->sk). This is done because newsocket
 * does not yet have its sock struct attached yet. Then on security_sock_graft
 * we can use the map to get the listen sk of the newsk being grafted. Here
 * we create the accept event along with update the tcpsocketmap and socketmaps.
 */

static inline __attribute__((always_inline)) int
__security_socket_accept(struct sock *sk, struct socket *newsocket)
{
	u64 cookie = (u64)newsocket;

	map_update_elem(&tg_l3_tcp_accsk, &cookie, &sk, 0);
	return 0;
}

static inline __attribute__((always_inline)) int
__security_sock_graft(void *ctx, struct sock *sk, struct socket *parent)
{
	struct socketmap_value *listen_process = 0;
	struct tcp_event_disable_config *event_cfg;
	struct tcpsocketmap_value *accept_socket;
	struct msg_ip_event *event;
	u64 now = tg_get_ktime();
	struct cfg_value *l3cfg;
	u16 family, protocol;
	u32 zero = 0;

	u64 *cookie, listen_cookie = 0;
	u64 cookie_version = 0;
	u64 newcookie, parent_cookie = (u64)parent;

	probe_read_kernel(&family, sizeof(family), _(&(sk->__sk_common.skc_family)));

	if (family != AF_INET && family != AF_INET6)
		return 0;

	cookie = (u64 *)map_lookup_elem(&tg_l3_tcp_accsk, &parent_cookie);
	if (likely(cookie)) {
		listen_cookie = (u64)*cookie;
		listen_process = lookup_socketmap(&listen_cookie);
	}
	newcookie = (u64)sk;

	/* This is to handle the case where a socket is blocking on accept
	 * when Tetragon started. In this case the socket created on accept()
	 * will not have an entry yet in the tg_l3_tcp_accsk.
	 * Nor will it have an entry in the socketmap because the socket
	 * create was before starting Tetragon as well. This means we will
	 * not be able to find its parent listen socket. So we need to find
	 * listen process directly. However, its rare and next accept will
	 * work so mark it unlikely.
	 */
	if (unlikely(!listen_process)) {
		struct execve_map_value *value;
		bool walked;
		u32 ppid;

		listen_process = (struct socketmap_value *)map_lookup_elem(&tg_h_tcplstn_ps, &zero);
		if (!listen_process)
			return 0;

		value = event_find_curr(&ppid, &walked);
		if (!value)
			return 0;
		listen_process->key.pid = value->key.pid;
		listen_process->key.ktime = value->key.ktime;
		listen_process->create_time = tg_get_ktime();
		listen_process->version = 0;
		listen_process->protocol = IPPROTO_TCP;
		memset(&listen_process->pad, 0, 7);
		add_socketmap(&listen_cookie, listen_process, 0, false);
	}

	cookie_version = cookie_inc_version();
	accept_socket = init_tcpsocketmap_value(&listen_process->key, SOCKFLAGS_TYPE_ACCEPT, now, cookie_version, 0);
	if (!accept_socket)
		return 0;

	if (family == AF_INET6) {
		accept_socket->tuple.ipv6 = 1;
		probe_read_kernel(accept_socket->tuple.saddr, sizeof(accept_socket->tuple.saddr), _(&(sk->__sk_common.skc_v6_rcv_saddr)));
		probe_read_kernel(accept_socket->tuple.daddr, sizeof(accept_socket->tuple.daddr), _(&(sk->__sk_common.skc_v6_daddr)));
	} else {
		accept_socket->tuple.ipv6 = 0;
		probe_read_kernel(&accept_socket->tuple.saddr[0], sizeof(__u32), _(&(sk->__sk_common.skc_rcv_saddr)));
		accept_socket->tuple.saddr[1] = 0;
		probe_read_kernel(&accept_socket->tuple.daddr[0], sizeof(__u32), _(&(sk->__sk_common.skc_daddr)));
		accept_socket->tuple.daddr[1] = 0;
	}
	probe_read_kernel(&protocol, sizeof(protocol), _(&(sk->sk_protocol)));
	if (bpf_core_field_size(sk->sk_protocol) == sizeof(u32)) {
		protocol >>= 8;
	}
	accept_socket->tuple.proto = protocol;
	probe_read_kernel(&accept_socket->tuple.sport, sizeof(accept_socket->tuple.sport), _(&(sk->__sk_common.skc_num)));
	probe_read_kernel(&accept_socket->tuple.dport, sizeof(accept_socket->tuple.dport), _(&(sk->__sk_common.skc_dport)));
	accept_socket->tuple.dport = bpf_ntohs(accept_socket->tuple.dport);
	accept_socket->tuple.conn_id = 0;

	// This if (1) block is here to help compiler with stack allocation
	// this is enough to keep stack limit below 512.
	if (1) {
		struct socketmap_value accept_process = *listen_process;

		accept_process.version = cookie_version;
		accept_process.create_time = now;
		add_socketmap(&newcookie, &accept_process, &accept_socket->tuple, true);
	}

	// Don't need to add the tuple because add_socketmap() will already have done so.
	add_tcpsocketmap(&newcookie, accept_socket, false);

	l3cfg = getl3cfg();
	if (!l3cfg)
		return 0;
	event_cfg = &l3cfg->tcp_disable;

	if (!event_cfg->disableAccept) {
		size_t size = sizeof(struct msg_ip_event);

		event = (struct msg_ip_event *)map_lookup_elem(&tg_h_event,
							       &zero);
		if (!event)
			return 0;

		event->common.op = ISO_MSG_OP_TCPACCEPT;
		event->common.size = sizeof(struct msg_ip_event);
		event->common.ktime = now;
		event->ret = 0;
		event->socket_cookie = newcookie;
		event->socket_flags = SOCKFLAGS_TYPE_ACCEPT;
		event->version = cookie_version;
		event->create_time = now;
		event->close_time = 0;

		event->tuple = accept_socket->tuple;
		event->key = listen_process->key;

		perf_event_output_metric(ctx, ISO_MSG_OP_TCPACCEPT, &tcpmon_map, BPF_F_CURRENT_CPU, event, size);
	}
	return 0;
}

#endif
