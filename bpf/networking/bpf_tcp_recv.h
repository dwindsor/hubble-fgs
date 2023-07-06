#ifndef __BPF_TCP_RECV_H_
#define __BPF_TCP_RECV_H_

#include "vmlinux.h"
#include "api.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "bpf_udp.h"
#include "bpf_latency.h"
#include "bpf_process_network_watermarks.h"
#include "cookie.h"
#include "bpf_network_helpers.h"
#include "address_family.h"
#include "bpf_tracing.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, u64);
	__uint(max_entries, 1);
} tcp_cookie_heap SEC(".maps");

static inline __attribute__((always_inline)) int
check_timestamp(struct timestamp_option *ts_opt, u64 *cookie)
{
	struct latency_config *latency_config = 0;
	struct latency_protocol_config *tcp_latency = 0;
	struct socketmap_value *process;
	int zero = 0;
	s64 latency = 0;

	latency_config = (struct latency_config *)map_lookup_elem(&latency_config_map, &zero);
	if (!latency_config) {
		return 1;
	}

	process = lookup_socketmap(cookie);
	if (!process) {
		return 1;
	}

	latency = calc_latency(latency_config->boot_ns,
			       bpf_ntohl(ts_opt->timestamp_low),
			       bpf_ntohl(ts_opt->timestamp_high));
	tcp_latency = &latency_config->tcp;

	add_latency(tcp_latency, process->latency_buckets, &process->latency_sum, latency);

	return 1;
}

static inline __attribute__((always_inline)) void
tcp_handler_lazy(struct __sk_buff *skb)
{
	struct iphdr ip;
	u64 *cookie;
	int zero = 0;
	struct timestamp_option ts_opt;
	u16 ethertype = bpf_ntohs((u16)skb->protocol);

	/* Only handle IPv4 and IPv6 here. */
	if (ethertype != ETH_P_IP && ethertype != ETH_P_IPV6)
		return;

	cookie = (u64 *)map_lookup_elem(&tcp_cookie_heap, &zero);
	if (!cookie)
		return;
	write_cookie(cookie, (u64)skb->sk);
	if (!*cookie) {
		emit_ip_error_event(skb, 0, cookie, false, 0, 1, 0, IP_ERROR_INET_NO_COOKIE);
		return;
	}

	if (skb_load_bytes(skb, 0, &ip, sizeof(struct iphdr)) < 0) {
		emit_ip_error_event(skb, 0, cookie, false, 0, 1, 0, IP_ERROR_INET_READ_VER);
		return;
	}

	switch (ip.version) {
	case 4:
		if (ip.protocol != IPPROTO_TCP)
			return;
		if (ip.ihl >= ((sizeof(struct iphdr) + sizeof(struct timestamp_option)) / sizeof(u32))) {
			/* Packet has at least enough space for the Timestamp IP Option,
			 * so check if the first option is the Timestamp option that we
			 * add to detect TCP latency.
			 */
			if (skb_load_bytes(skb, sizeof(struct iphdr), &ts_opt, sizeof(struct timestamp_option)) < 0) {
				emit_ip_error_event(skb, &ip, cookie, false, ip.version, 1, 0, IP_ERROR_INET_READ_IP_OPTION);
				return;
			}
			if (ts_opt.type != IPO_TYPE && ts_opt.magic != bpf_ntohl(IPO_MAGIC_W) && ts_opt.magic != ts_opt.magic2) {
				return;
			}
			check_timestamp(&ts_opt, cookie);
		}
		break;
	case 6:
		break;
	default:
		emit_ip_error_event(skb, 0, cookie, false, ip.version, 1, 0, IP_ERROR_INET_NO_VERSION);
		return;
	}
}

static inline __attribute__((always_inline)) void
tcp_handler(struct __sk_buff *skb)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (long *)(long)skb->data;
	struct iphdr *ip;
	u64 cookie;
	struct timestamp_option *ts_opt = 0;
	u16 ethertype = bpf_ntohs((u16)skb->protocol);

	/* Only handle IPv4 and IPv6 here. */
	if (ethertype != ETH_P_IP && ethertype != ETH_P_IPV6)
		return;

	write_cookie(&cookie, (u64)skb->sk);

	if (data + 1 > data_end) {
		emit_ip_error_event(skb, 0, &cookie, false, 0, 1, 0, IP_ERROR_INET_READ_VER);
		return;
	}

	ip = (struct iphdr *)data;

	switch (ip->version) {
	case 4:
		if (data + sizeof(struct iphdr) > data_end) {
			emit_ip_error_event(skb, 0, &cookie, false, ip->version, 1, 0, IP_ERROR_INET_READ_IP);
			return;
		}
		if (ip->protocol != IPPROTO_TCP)
			return;
		if (ip->ihl >= ((sizeof(struct iphdr) + sizeof(struct timestamp_option)) / sizeof(u32))) {
			/* Packet has at least enough space for the Timestamp IP Option,
			 * so check if the first option is the Timestamp option that we
			 * add to detect TCP latency.
			 */
			if (data + sizeof(struct iphdr) + sizeof(struct timestamp_option) > data_end) {
				emit_ip_error_event(skb, ip, &cookie, false, ip->version, 1, 0, IP_ERROR_INET_READ_IP_OPTION);
				return;
			}
			ts_opt = (struct timestamp_option *)(data + sizeof(struct iphdr));
			if (ts_opt->type != IPO_TYPE || ts_opt->magic != bpf_ntohl(IPO_MAGIC_W) || ts_opt->magic != ts_opt->magic2) {
				return;
			}
			check_timestamp(ts_opt, &cookie);
		}
		break;
	case 6:
		break;
	default:
		emit_ip_error_event(skb, 0, &cookie, false, ip->version, 1, 0, IP_ERROR_INET_NO_VERSION);
		return;
	}
}

#endif //__BPF_TCP_RECV_H_
