#ifndef __BPF_DISPATCHER__
#define __BPF_DISPATCHER__
#include "./icmp/bpf_icmp.h"
#include "./udp/bpf_udp_inet.h"
#include "./tcp/bpf_tcp_recv.h"

struct cgroup_dispatch_cfg {
	uint32_t icmp4;
	uint32_t icmp6;
	uint32_t tcp4;
	uint32_t tcp6;
	uint32_t udp4;
	uint32_t udp6;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct cgroup_dispatch_cfg);
	__uint(max_entries, 1);
} tg_cgroup_protocol_cfg_map SEC(".maps");

static inline __attribute__((always_inline)) int
tg_cgroup_dispatcher(struct __sk_buff *skb, int send)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (long *)(long)skb->data;
	struct cgroup_dispatch_cfg *cfg;
	struct handler_vars *vars;
	int ret = SK_PASS;
	struct iphdr *ip;
	u16 payload_off;
	int zero = 0;
	u8 protocol;

	vars = (struct handler_vars *)map_lookup_elem(&dispatcher_heap, &zero);
	if (!vars)
		return SK_PASS;

	write_cookie(&vars->cookie, (u64)skb->sk);

	if (!vars->cookie) {
		emit_ip_error_event(skb, 0, &vars->cookie, false, 0, 1, 0, IP_ERROR_INET_NO_COOKIE);
		return SK_PASS;
	}

	if (data + sizeof(struct iphdr) > data_end) {
		if (skb_load_bytes(skb, 0, &vars->ip, sizeof(struct iphdr)) < 0) {
			emit_ip_error_event(skb, 0, &vars->cookie, false, 0, 1, 0, IP_ERROR_INET_READ_VER);
			return SK_PASS;
		}
		ip = &vars->ip;
	} else
		ip = (struct iphdr *)data;

	cfg = (struct cgroup_dispatch_cfg *)map_lookup_elem(&tg_cgroup_protocol_cfg_map, &zero);
	if (!cfg)
		return SK_PASS;

	switch (ip->version) {
	case 4:
		if (ip->protocol == IPPROTO_UDP && cfg->udp4)
			ret = udp_handler_ip4(skb, send);
		else if (ip->protocol == IPPROTO_ICMP && cfg->icmp4)
			ret = icmp_handler_ip4(skb, send);
		else if (ip->protocol == IPPROTO_TCP && cfg->tcp4)
			ret = tcp_handler_ip4(skb, send);
		break;
	case 6:
		if (skb_load_bytes(skb, 0, &vars->ip6, sizeof(struct ipv6hdr)) < 0) {
			emit_ip_error_event(skb, 0, &vars->cookie, true, ip->version, send + 1, 0, IP_ERROR_INET_READ_IP);
			return SK_PASS;
		}
		protocol = get_ip6_proto(&payload_off, &vars->ip6, 0, skb, data, data_end, false, 0);
		if (protocol == IP_HEADER_ERROR) {
			emit_ip_error_event(skb, &vars->ip6, &vars->cookie, true, ip->version, send + 1, 0, IP_ERROR_INET_READ_IP);
			return SK_PASS;
		} else if (protocol == IPPROTO_UDP && cfg->udp6) {
			udp_handler_ip6(skb, &vars->ip6, &vars->cookie, payload_off, send);
		} else if (protocol == IPPROTO_TCP && cfg->tcp6) {
			ret = tcp_handler_ip6(skb, &vars->ip6, &vars->cookie, payload_off, send);
		} else if (protocol == IPPROTO_ICMP6 && cfg->icmp6) {
			icmp_handler_ip6(skb, &vars->ip6, &vars->cookie, payload_off, send);
		}
		break;
	}

	return ret;
}
#endif
