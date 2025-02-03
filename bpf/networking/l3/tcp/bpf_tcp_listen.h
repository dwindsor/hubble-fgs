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

#ifndef __BPF_TCP_LISTEN_H__
#define __BPF_TCP_LISTEN_H__

#include "vmlinux.h"

#include "api.h"
#include "iso_msg_types.h"
#include "bpf_task.h"
#include "bpf_cookie.h"
#include "lib/netns.h"
#include "lib/tlsmsg.h"
#include "bpf_fd_to_sk.h"
#include "bpf_tracing.h"
#include "bpf_tcp_network_event_config.h"
#include "lib/address_family.h"
#include "bpf_tcp_info.h"
#include "bpf_network_helpers.h"
#include "bpf_tcp_state.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct msg_ip_event);
	__uint(max_entries, 1);
} tcp_listen_event_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, __u64);
	__uint(max_entries, 32000);
} tg_tcp_accept_socket_to_sk_map SEC(".maps");

static inline __attribute__((always_inline)) int
__event_sys_listen(void *ctx, struct sock *skp)
{
	struct tcp_event_disable_config *event_cfg;
	struct execve_map_value *process = 0;
	struct socketmap_value *socket = 0;
	struct tcpsocketmap_value *v = 0;
	struct msg_execve_key *key = 0;
	__u32 pid, ppid = 0, zero = 0;
	struct msg_ip_event *val;
	bool walker = 0;
	u16 family;
	u64 cookie;

	pid = (get_current_pid_tgid() >> 32);
	/* In TCP we use the struct sock address as the socket cookie.
	 */
	cookie = (u64)skp;

	socket = lookup_socketmap(&cookie);
	if (socket) {
		key = &socket->key;
		// Set the protocol here because it probably wasn't specified at the time of
		// socket allocation.
		socket->protocol = IPPROTO_TCP;
	} else {
		process = event_find_curr(&ppid, &walker);
		if (!process) {
			emit_ip_error_event(ctx, 0, &cookie, false, 0, 0, 0, IP_ERROR_TCP_LISTEN_NO_PROCESS);
			return 0;
		}
		key = &process->key;
	}

	val = (struct msg_ip_event *)map_lookup_elem(&tcp_listen_event_map,
						     &zero);
	if (!val) {
		return 0;
	}

	*val = (struct msg_ip_event){
		.tuple.daddr[0] = 0,
		.tuple.daddr[1] = 0,
		.tuple.dport = 0,
		.tuple.proto = IPPROTO_TCP,
		.common.op = ISO_MSG_OP_LISTEN,
		.common.ktime = ktime_get_ns(),
		.common.size = sizeof(struct msg_ip_event),
		.key.pid = pid,
		.key.ktime = key->ktime,
		.socket_cookie = cookie,
		.socket_flags = 0,
		.version = 0,
		.create_time = 0,
		.close_time = 0,
	};
	if (socket)
		val->version = socket->version;

	probe_read_kernel(&family, sizeof(family), _(&(skp->__sk_common.skc_family)));

	probe_read_kernel(&val->tuple.sport, sizeof(val->tuple.sport),
			  _(&(skp->__sk_common.skc_num)));

	if (family != AF_INET6) {
		val->tuple.ipv6 = false;
		probe_read_kernel(&val->tuple.saddr[0], sizeof(__u32),
				  _(&(skp->__sk_common.skc_rcv_saddr)));
		val->tuple.saddr[1] = 0;
	} else {
		val->tuple.ipv6 = true;
		probe_read_kernel(&val->tuple.saddr[0], sizeof(val->tuple.saddr),
				  _(&(skp->__sk_common.skc_v6_rcv_saddr)));
	}
	event_cfg = (struct tcp_event_disable_config *)map_lookup_elem(
		&tg_event_disable_config, &zero);
	if (!event_cfg)
		return 0;

	if (!event_cfg->disableListen) {
		perf_event_output_metric(ctx, ISO_MSG_OP_LISTEN, &tcpmon_map, BPF_F_CURRENT_CPU, val,
					 sizeof(struct msg_ip_event));
	}

	if (key && socket)
		v = init_tcpsocketmap_value(key, family, SOCKFLAGS_TYPE_LISTEN, socket->create_time, socket->version, &val->tuple);
	if (v)
		add_tcpsocketmap(&cookie, v, &val->tuple, true);

	return 0;
}

#endif //__BPF_TCP_LISTEN_H__
