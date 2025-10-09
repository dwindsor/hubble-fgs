#ifndef __BPF_DISPATCHER__
#define __BPF_DISPATCHER__
#include "./icmp/bpf_icmp.h"
#include "./udp/bpf_udp_inet.h"
#include "./tcp/bpf_tcp_recv.h"
#include "config.h"

volatile __CONST bool CGROUP_PROBE_READ = false;

int tg_cgroup_dispatcher(struct __sk_buff *skb, int send)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (long *)(long)skb->data;
	struct cgroup_dispatch_cfg *cfg;
	struct handler_vars *vars;
	struct cfg_value *l3cfg;
	int ret = SK_PASS;
	struct iphdr *ip;
	u16 payload_off;
	int zero = 0;
	u8 protocol;

	vars = (struct handler_vars *)map_lookup_elem(&tg_p_l3_dsptchr, &zero);
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

	l3cfg = getl3cfg();
	if (!l3cfg)
		return SK_PASS;
	cfg = &l3cfg->proto;

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
			udp_handler_ip6(skb, payload_off, send);
		} else if (protocol == IPPROTO_TCP && cfg->tcp6) {
			ret = tcp_handler_ip6(skb, payload_off, send);
		} else if (protocol == IPPROTO_ICMP6 && cfg->icmp6) {
			icmp_handler_ip6(skb, payload_off, send);
		}
		break;
	}

	return ret;
}
#endif
