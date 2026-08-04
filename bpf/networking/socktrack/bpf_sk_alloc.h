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
#include "bpf_task.h"
#include "../bpf_cookie.h"
#include "../bpf_network_helpers.h"
#include "bpf_tracing.h"
#include "../l3/tcp/bpf_tcp_close.h"
#include "l3_config.h"
#include "bpf_event_map.h"

static inline __attribute__((always_inline)) void
emit_sk_event(void *ctx, struct socketmap_value *process, u64 cookie, u8 op)
{
	struct msg_ip_event *e;
	int zero = 0;

	e = (struct msg_ip_event *)map_lookup_elem(&tg_h_event, &zero);
	if (!e)
		return;

	e->common.op = op;
	e->common.size = sizeof(struct msg_ip_event);
	e->common.ktime = tg_get_ktime();
	e->key.pid = process->key.pid;
	e->key.ktime = process->key.ktime;
	e->socket_cookie = cookie;
	e->version = process->version;
	e->tuple.ipv6 = 0;
	e->tuple.saddr[0] = 0;
	e->tuple.saddr[1] = 0;
	e->tuple.daddr[0] = 0;
	e->tuple.daddr[1] = 0;
	e->tuple.sport = 0;
	e->tuple.dport = 0;
	e->create_time = process->create_time;
	e->close_time = e->common.ktime; // ignored on create messages.

	perf_event_output_metric(ctx, op, &tcpmon_map, BPF_F_CURRENT_CPU, e,
				 sizeof(struct msg_ip_event));
}

static inline __attribute__((always_inline)) int
store_socket(void *ctx, u64 cookie, u8 protocol)
{
	u64 pid = get_current_pid_tgid() >> 32;
	struct socketmap_value process = { 0 };
	struct execve_map_value *value;
	struct cfg_value *cfg;
	bool walked;
	u32 ppid;

	if (!cookie) {
		emit_ip_error_event(ctx, 0, 0, false,
				    0, 0, 0, IP_ERROR_SOCK_CREATE_NO_COOKIE);
		return 0;
	}

	if (pid < 1) {
		// We are in kernel context so we can't attribute this socket to
		// a user space process. This can happen because the kernel has
		// created a kernel socket (which we don't track), or because a
		// listening socket has spawned an accepted socket (which we deal
		// with by updating the socketmap in the accept programs). All
		// user space socket creations are via socket() which should be
		// in the user process context. These are therefore not errors.
		return 0;
	}

	/* Ideally we would be able to bind the socket to create early,
	 * but its possible that we don't have an entry for the thread
	 * if its a child thread, etc. Perhaps we should always have
	 * entries, but we don't at the moment. So to ensure we don't
	 * mislead the next layer to process this we not only need to
	 * check if the entry exists but also that ktime!=0 which would
	 * indicate its a stale entry that we are preparing to GC.
	 */
	value = event_find_curr(&ppid, &walked);
	if (value && value->key.ktime) {
		process.key.pid = value->key.pid;
		process.key.ktime = value->key.ktime;
	} else {
		emit_ip_error_event(ctx, 0, &cookie, false,
				    0, 0, 0, IP_ERROR_SOCK_CREATE_NO_PROCESS);
		return 1;
	}
	process.create_time = tg_get_ktime();
	process.protocol = protocol;
	process.version = cookie_inc_version();
	// Don't update the tuple map here because the socket hasn't yet
	// been populated, and might be ICMP or raw without a tuple.
	add_socketmap(&cookie, &process, 0, false);

	cfg = getl3cfg();
	if (!cfg)
		return 0;

	if (protocol == IPPROTO_RAW && cfg->raw_enabled)
		emit_sk_event(ctx, &process, cookie, ISO_MSG_OP_RAWSOCK_CREATE);
	return 0;
}

static inline __attribute__((always_inline)) int
destroy_socket(void *ctx, u64 cookie)
{
	struct udp_sensor_config *udp_cfg;
	struct tcpsocketmap_value *socket;
	struct socketmap_value *process;
	struct cfg_value *cfg;

	process = lookup_socketmap(&cookie);
	if (!process)
		return 0;

	cfg = getl3cfg();
	if (cfg) {
		udp_cfg = &cfg->udp;
		switch (process->protocol) {
		case IPPROTO_UDP:
			// UDP close events can be disabled by either disabling the UDP protocol,
			// or specifically disabling close events in the UDP config.
			if (cfg->udp_report_close && !udp_cfg->disable_close_events)
				emit_sk_event(ctx, process, cookie, ISO_MSG_OP_UDPCLOSE);
			break;
		case IPPROTO_RAW:
			if (cfg->raw_report_close)
				emit_sk_event(ctx, process, cookie, ISO_MSG_OP_RAWSOCK_CLOSE);
			break;
		case IPPROTO_TCP:
			socket = lookup_tcpsocketmap(&cookie);
			if (socket && !socket->closed)
				__event_tcp_close(ctx, (struct sock *)cookie, TCP_CLOSE);
			del_tcpsocketmap(&cookie);
			map_delete_elem(&tg_l3_tcp_finrx, &cookie);
			break;
		}
	}

	del_socketmap(&cookie);
	return 1;
}
