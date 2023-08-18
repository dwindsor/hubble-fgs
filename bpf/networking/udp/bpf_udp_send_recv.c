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
