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
#include "bpf_tracing.h"
#include "bpf_rawsock.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct msg_ip_event);
	__uint(max_entries, 1);
} raw_close_event_map SEC(".maps");

__attribute__((section("kprobe/__sk_free"), used)) int
tg_rawsock_sk_free(struct pt_regs *ctx)
{
	__u64 cookie = (__u64)PT_REGS_PARM1(ctx);
	struct socketmap_value *process;

	process = lookup_socketmap(&cookie);
	if (!process || process->protocol != IPPROTO_RAW)
		return 1;
	emit_rawsock_event(ctx, process, cookie, ISO_MSG_OP_RAWSOCK_CLOSE);
	del_socketmap(&cookie);
	return 1;
}
