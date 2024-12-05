// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#include "bpf_tcp_rtt.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

SEC("fentry/tcp_ack_update_rtt")
int BPF_PROG(tg_tcp_ack_update_rtt, struct sock *skp, u32 flag, s64 seq_rtt_us, s64 sack_rtt_us)
{
	__tcp_ack_update_rtt(ctx, (struct tcp_sock *)skp, flag, seq_rtt_us, sack_rtt_us);
	return 0;
}
