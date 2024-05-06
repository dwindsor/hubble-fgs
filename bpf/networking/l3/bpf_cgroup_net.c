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
#include "./icmp/bpf_icmp.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

int tg_cgroup_dispatcher(struct __sk_buff *skb, int send)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (long *)(long)skb->data;
	struct ipv6hdr ip6;
	int ret = SK_PASS;
	struct iphdr ip;
	u16 payload_off;
	u64 cookie;
	u8 protocol;

	write_cookie(&cookie, (u64)skb->sk);

	if (skb_load_bytes(skb, 0, &ip, sizeof(struct iphdr)) < 0) {
		emit_ip_error_event(skb, 0, &cookie, false, 0, 1, 0, IP_ERROR_INET_READ_VER);
		return SK_PASS;
	}

	switch (ip.version) {
	case 4:
		if (ip.protocol == IPPROTO_ICMP)
			ret = icmp_handler_ip4(skb, &ip, &cookie, send);

	case 6:
		if (skb_load_bytes(skb, 0, &ip6, sizeof(struct ipv6hdr)) < 0) {
			emit_ip_error_event(skb, 0, &cookie, true, ip.version, 1, 0, IP_ERROR_INET_READ_IP);
			return SK_PASS;
		}

		protocol = get_ip6_proto(&payload_off, &ip6, 0, data, data_end, 0, false, 0);
		if (protocol == IP_HEADER_ERROR) {
			emit_ip_error_event(skb, &ip6, &cookie, true, ip.version, 1, 0, IP_ERROR_INET_READ_IP);
			return SK_PASS;
		}

		if (protocol == IPPROTO_ICMP6)
			icmp_handler_ip6(skb, &ip6, &cookie, payload_off, send);
	}

	return ret;
}

__attribute__((section("cgroup_skb/ingress"), used)) int
tg_cgroup_ingress(struct __sk_buff *skb)
{
	return tg_cgroup_dispatcher(skb, 0);
}

__attribute__((section("cgroup_skb/egress"), used)) int
tg_cgroup_egress(struct __sk_buff *skb)
{
	return tg_cgroup_dispatcher(skb, 1);
}
