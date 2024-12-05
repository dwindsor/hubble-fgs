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
#include "bpf_rawsock_create.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

SEC("fentry/raw_sk_init")
int BPF_PROG(tg_rawsock_sk_init, struct sock *sk)
{
	u64 cookie = (u64)sk;

	__rawsock_sk_init(ctx, cookie);
	return 0;
}

// IPv6 version
SEC("fentry/rawv6_init_sk")
int BPF_PROG(tg_rawsockv6_init_sk, struct sock *sk)
{
	u64 cookie = (u64)sk;

	__rawsock_sk_init(ctx, cookie);
	return 0;
}
