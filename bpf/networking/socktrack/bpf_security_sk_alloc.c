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
#include "bpf_sk_alloc.h"
#include "../../lib/address_family.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

SEC("fentry/security_sk_alloc")
int BPF_PROG(tg_security_sk_alloc, struct sock *sk, int family, int priority)
{
	u64 cookie = (u64)sk;
	u16 skc_num = 0;

	/* Only handle IPv4, IPv6 and raw sockets. */
	if (family != AF_INET && family != AF_INET6 && family != AF_PACKET)
		return 0;
	if (!cookie)
		return 0;

	if (family == AF_PACKET)
		skc_num = IPPROTO_RAW;
	store_socket(ctx, cookie, skc_num);
	return 0;
}

SEC("fentry/security_sk_free")
int BPF_PROG(tg_security_sk_free, struct sock *sk)
{
	u64 cookie = (u64)sk;
	u16 family;

	if (!sk)
		return 0;
	probe_read_kernel(&family, sizeof(family), _(&(sk->__sk_common.skc_family)));
	/* Only handle IPv4, IPv6 and raw sockets. */
	if (family != AF_INET && family != AF_INET6 && family != AF_PACKET)
		return 0;

	destroy_socket(ctx, cookie);
	return 0;
}
