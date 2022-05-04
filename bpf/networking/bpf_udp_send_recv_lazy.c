#include "bpf_udp_send_recv.h"

__attribute__((section(("kprobe/udp_sendmsg")), used)) int
udp4_send_kprobe(struct pt_regs *ctx)
{
	return udp4_send(ctx);
}

__attribute__((section(("kretprobe/udp_sendmsg")), used)) int
udp4_sendret_kprobe(struct pt_regs *ctx)
{
	return udp4_sendret(ctx, true);
}

__attribute__((section(("kprobe/__skb_recv_udp")), used)) int
udp4_recv_kprobe(struct pt_regs *ctx)
{
	return udp4_recv(ctx);
}

__attribute__((section(("kretprobe/__skb_recv_udp")), used)) int
udp4_recvret_kprobe(struct pt_regs *ctx)
{
	return udp4_recvret(ctx, true);
}
