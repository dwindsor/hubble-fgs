#include "vmlinux.h"
#include "bpf_tls_inet_send.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

__attribute__((section("cgroup_skb/egress"), used)) int
tls_inet_send(struct __sk_buff *skb)
{
	struct tls_packet_details *packet;
	u64 cookie = (u64)skb->sk;

	packet = tls_inet_send_handler(skb, 1);
	if (!packet)
		return SK_PASS;
	bpf_parse_tls_egress(skb, &cookie, packet->payload_off);
	return SK_PASS;
}

__attribute__((section("cgroup_skb/ingress"), used)) int
tls_inet_recv(struct __sk_buff *skb)
{
	struct tls_packet_details *packet;

	packet = tls_inet_send_handler(skb, 0);
	if (!packet)
		return SK_PASS;
	bpf_parse_ingress_skb(skb, packet->payload_off);
	return SK_PASS;
}
