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
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_tcp_info.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

static inline __attribute__((always_inline)) int
__event_tcp_rst(void *ctx, struct sock *sk)
{
	struct tcpsocketmap_value *socket;
	__u64 cookie = (__u64)sk;

	socket = lookup_tcpsocketmap(&cookie);
	if (!socket)
		return 0;

	// We only change the flags at socket creation, so we shouldn't have a race
	// condition here.
	socket->socket_flags |= SOCKFLAGS_CONNECTION_RESET;

	return 0;
}