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

#include "compiler.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "bpf_process_event.h"
#include "bpf_execve_event.h"
#include "bpf_helpers.h"
#include "bpf_rate.h"
#include "errmetrics.h"
#include "bpf_mbset.h"
#include "bpf_ktime.h"
#include "environ_conf.h"
#include "lib/common.h"

#define MAX_SELECTORS 5
#include "policy_filter.h"
#include "process_tree.h"

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";

FUNC_INLINE int
ee_execve_send(struct bpf_raw_tracepoint_args *ctx,
	       struct msg_execve_event *event)
{
	execve_send_event(ctx, event);
	insert_process_tree();
	return 0;
}

__attribute__((section("raw_tracepoint/sys_execve"), used)) int
event_execve(struct bpf_raw_tracepoint_args *ctx)
{
	struct msg_execve_event *event;
	__u32 zero = 0;

	event = map_lookup_elem(&execve_msg_heap_map, &zero);
	if (!event)
		return 0;

	execve_event_init(ctx, event);

	if (execve_rate_check(ctx, event))
		return ee_execve_send(ctx, event);
	return 0;
}
