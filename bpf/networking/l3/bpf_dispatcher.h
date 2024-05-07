#ifndef __BPF_DISPATCHER__
#define __BPF_DISPATCHER__
#include "./icmp/bpf_icmp.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, u64);
	__uint(max_entries, 1);
} cgroup_cookie_heap SEC(".maps");

int tg_cgroup_dispatcher(struct __sk_buff *skb, int send)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (long *)(long)skb->data;
	struct ipv6hdr ip6;
	int ret = SK_PASS;
	struct iphdr ip;
	u16 payload_off;
	int zero = 0;
	u64 *cookie;
	u8 protocol;

	cookie = (u64 *)map_lookup_elem(&cgroup_cookie_heap, &zero);
	if (!cookie)
		return SK_PASS;
	write_cookie(cookie, (u64)skb->sk);

	if (!*cookie) {
		emit_ip_error_event(skb, 0, cookie, false, 0, 1, 0, IP_ERROR_INET_NO_COOKIE);
		return SK_PASS;
	}

	if (skb_load_bytes(skb, 0, &ip, sizeof(struct iphdr)) < 0) {
		emit_ip_error_event(skb, 0, cookie, false, 0, 1, 0, IP_ERROR_INET_READ_VER);
		return SK_PASS;
	}

	switch (ip.version) {
	case 4:
		if (ip.protocol == IPPROTO_ICMP)
			ret = icmp_handler_ip4(skb, &ip, cookie, send);

	case 6:
		if (skb_load_bytes(skb, 0, &ip6, sizeof(struct ipv6hdr)) < 0) {
			emit_ip_error_event(skb, 0, cookie, true, ip.version, 1, 0, IP_ERROR_INET_READ_IP);
			return SK_PASS;
		}

		protocol = get_ip6_proto(&payload_off, &ip6, 0, data, data_end, 0, false, 0);
		if (protocol == IP_HEADER_ERROR) {
			emit_ip_error_event(skb, &ip6, cookie, true, ip.version, 1, 0, IP_ERROR_INET_READ_IP);
			return SK_PASS;
		}

		if (protocol == IPPROTO_ICMP6)
			icmp_handler_ip6(skb, &ip6, cookie, payload_off, send);
	}

	return ret;
}
#endif
