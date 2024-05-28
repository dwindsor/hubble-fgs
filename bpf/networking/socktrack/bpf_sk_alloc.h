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

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct msg_ip_event);
	__uint(max_entries, 1);
} sk_event_heap SEC(".maps");

static inline __attribute__((always_inline)) void
emit_sk_event(void *ctx, struct socketmap_value *process, u64 cookie, u8 op)
{
	struct msg_ip_event *e;
	int zero = 0;

	e = (struct msg_ip_event *)map_lookup_elem(&sk_event_heap, &zero);
	if (!e)
		return;

	e->common.op = op;
	e->common.size = sizeof(struct msg_ip_event);
	e->common.ktime = ktime_get_ns();
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
	e->duration = 0;

	switch (op) {
	case ISO_MSG_OP_UDPCLOSE:
		/* Fill in the current time as a place-holder for the duration. We will
                * calculate the actual duration when we walk all the pseudo-sockets
                * associated with this socket.
                */
		e->duration = e->common.ktime;
		break;
	case ISO_MSG_OP_RAWSOCK_CLOSE:
		e->duration = e->common.ktime - process->create_time;
		break;
	}

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
	int zero = 0;
	bool walked;
	u32 ppid;

	if (!cookie) {
		emit_ip_error_event(ctx, 0, 0, false,
				    0, 0, 0, IP_ERROR_SOCK_CREATE_NO_COOKIE);
		return 0;
	}

	if (pid < 1) {
		emit_ip_error_event(ctx, 0, &cookie, false,
				    0, 0, 0, IP_ERROR_SOCK_CREATE_PID_0);
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
	process.create_time = ktime_get_ns();
	process.protocol = protocol;
	process.version = cookie_inc_version();
	// Don't update the tuple map here because the socket hasn't yet
	// been populated, and might be ICMP or raw without a tuple.
	add_socketmap(&cookie, &process, false);

	cfg = map_lookup_elem(&tg_cfg_map, &zero);
	if (!cfg)
		return 0;

	if (protocol == IPPROTO_RAW && cfg->raw_enabled)
		emit_sk_event(ctx, &process, cookie, ISO_MSG_OP_RAWSOCK_CREATE);
	return 0;
}

static inline __attribute__((always_inline)) int
destroy_socket(void *ctx, u64 cookie)
{
	struct socketmap_value *process;
	struct cfg_value *cfg;
	int zero = 0;

	process = lookup_socketmap(&cookie);
	if (!process)
		return 0;

	cfg = (struct cfg_value *)map_lookup_elem(&tg_cfg_map, &zero);
	if (cfg) {
		switch (process->protocol) {
		case IPPROTO_UDP:
			if (cfg->udp_report_close)
				emit_sk_event(ctx, process, cookie, ISO_MSG_OP_UDPCLOSE);
			break;
		case IPPROTO_RAW:
			if (cfg->raw_report_close)
				emit_sk_event(ctx, process, cookie, ISO_MSG_OP_RAWSOCK_CLOSE);
			break;
		}
	}

	del_socketmap(&cookie);
	return 1;
}
