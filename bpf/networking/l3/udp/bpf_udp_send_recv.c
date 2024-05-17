// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#include "bpf_udp_send_recv.h"

__attribute__((section("kprobe/udp_sendmsg"), used)) int
tg_udp4_send_kprobe(struct pt_regs *ctx)
{
	return udp_send(ctx);
}

__attribute__((section("kretprobe/udp_sendmsg"), used)) int
tg_udp4_sendret_kprobe(struct pt_regs *ctx)
{
	return udp_sendret(ctx, false);
}

__attribute__((section("kprobe/udpv6_sendmsg"), used)) int
tg_udp6_send_kprobe(struct pt_regs *ctx)
{
	return udp_send(ctx);
}

__attribute__((section("kretprobe/udpv6_sendmsg"), used)) int
tg_udp6_sendret_kprobe(struct pt_regs *ctx)
{
	return udp_sendret(ctx, true);
}

__attribute__((section("kprobe/skb_consume_udp"), used)) int
tg_udp_recv_kprobe(struct pt_regs *ctx)
{
	return udp_recv(ctx);
}
