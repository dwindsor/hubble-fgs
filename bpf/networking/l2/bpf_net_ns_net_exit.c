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
#include "iso_msg_types.h"
#include "bpf_tracing.h"

struct msg_netns_exit {
	struct msg_common common;
	__u64 inum;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct msg_netns_exit);
	__uint(max_entries, 1);
} netns_exit_heap SEC(".maps");

__attribute__((section("kprobe/net_ns_net_exit"), used)) int
net_ns_net_exit(struct pt_regs *ctx)
{
	struct net *net = (struct net *)PT_REGS_PARM1(ctx);
	struct msg_netns_exit *val;
	struct ns_common nscommon;
	int zero = 0;

	probe_read_kernel(&nscommon, sizeof(nscommon), _(&(net->ns)));

	val = map_lookup_elem(&netns_exit_heap, &zero);
	if (!val)
		return 1;
	val->common.op = ISO_MSG_OP_NETNS_EXIT;
	val->common.size = sizeof(struct msg_netns_exit);
	val->inum = nscommon.inum;

	perf_event_output_metric(ctx, ISO_MSG_OP_NETNS_EXIT, &tcpmon_map, BPF_F_CURRENT_CPU, val,
				 sizeof(struct msg_netns_exit));
	return 0;
}

char _license[] __attribute__((section("license"), used)) = "GPL";
