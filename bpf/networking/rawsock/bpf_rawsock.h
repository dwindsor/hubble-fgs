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
	__type(key, int);
	__type(value, struct msg_ip_event);
	__uint(max_entries, 1);
} rawsock_event_heap SEC(".maps");

static inline __attribute__((always_inline)) void
emit_rawsock_event(void *ctx, struct socketmap_value *process, u64 cookie, u8 op)
{
	struct msg_ip_event *e;
	int zero = 0;

	e = (struct msg_ip_event *)map_lookup_elem(&rawsock_event_heap, &zero);
	if (!e)
		return;

	e->common.op = op;
	e->common.size = sizeof(struct msg_ip_event);
	e->common.ktime = ktime_get_ns();
	e->key.pid = process->key.pid;
	e->key.ktime = process->key.ktime;
	e->socket_cookie = cookie;
	if (op == ISO_MSG_OP_RAWSOCK_CREATE) {
		e->duration = 0;
	} else {
		e->duration = ktime_get_ns() - process->create_time;
	}
	perf_event_output_metric(ctx, op, &tcpmon_map, BPF_F_CURRENT_CPU, e,
				 sizeof(struct msg_ip_event));
}