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
#include "bpf_cookie.h"
#include "bpf_network_helpers.h"
#include "bpf_tracing.h"
#include "socktrack/bpf_sk_alloc.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

static inline __attribute__((always_inline)) int
store_socket(void *ctx, u64 cookie, u8 protocol);

// Raw sockets are used for ping in some environments.
// These are handled by the rawsock programs.
// Ping sockets are used for ping in other environments (handles IPv4 and IPv6)
__attribute__((section("kprobe/ping_init_sock"), used)) int
tg_ping_init_sock(struct pt_regs *ctx)
{
	u64 cookie = (u64)PT_REGS_PARM1(ctx);

	return store_socket(ctx, cookie, IPPROTO_ICMP);
}
