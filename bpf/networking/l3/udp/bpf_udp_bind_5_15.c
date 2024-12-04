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
#include "bpf_tracing.h"
#include "bpf_udp_bind.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

enum cgroup_bpf_attach_type {
	CGROUP_INET4_POST_BIND,
	CGROUP_INET6_POST_BIND
};

__attribute__((section("kprobe/__cgroup_bpf_run_filter_sk"), used)) int
tg_udp_bind_sock(struct pt_regs *ctx)
{
	__u64 cookie = PT_REGS_PARM1(ctx);
	int attach = PT_REGS_PARM2(ctx);

	if (attach == bpf_core_enum_value(enum cgroup_bpf_attach_type, CGROUP_INET4_POST_BIND)) {
		return __udp_bind_sock(ctx, cookie, false);
	} else if (attach == bpf_core_enum_value(enum cgroup_bpf_attach_type, CGROUP_INET6_POST_BIND)) {
		return __udp_bind_sock(ctx, cookie, true);
	}

	return 1;
}
