#ifndef __BPF_ICMP_H_
#define __BPF_ICMP_H_

#include "vmlinux.h"
#include "api.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "../cookie.h"
#include "../bpf_network_helpers.h"
#include "address_family.h"

#define ICMP_HDR_LEN	  8
#define ICMP_HDR_DATA_OFF 4

#define ICMP_ECHOREPLY 0
#define ICMP_ECHO      8

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, u64);
	__uint(max_entries, 1);
} icmp_cookie_heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct msg_icmp_event);
	__uint(max_entries, 1);
} icmp_event_heap SEC(".maps");

static inline __attribute__((always_inline)) void
send_icmp_event(void *ctx, struct msg_icmp_event *val, u64 *cookie)
{
	struct socketmap_value *process;

	process = lookup_socketmap(cookie);
	if (process) {
		val->key.pid = process->key.pid;
		val->key.ktime = process->key.ktime;
	} else {
		val->key.pid = 0;
		val->key.ktime = 1;
	}
	val->common.ktime = ktime_get_ns();
	val->common.size = sizeof(struct msg_icmp_event);
	val->socket_cookie = *cookie;
	perf_event_output_metric(ctx, ISO_MSG_OP_ICMP, &tcpmon_map, BPF_F_CURRENT_CPU, val,
				 sizeof(struct msg_icmp_event));
}

static inline __attribute__((always_inline)) void
icmp_handler_lazy(struct __sk_buff *skb, bool send)
{
	u8 icmp_data[ICMP_HDR_LEN];
	struct msg_icmp_event *val;
	struct iphdr ip;
	int zero = 0;
	u64 *cookie;

	cookie = (u64 *)map_lookup_elem(&icmp_cookie_heap, &zero);
	if (!cookie)
		return;
	write_cookie(cookie, (u64)skb->sk);

	if (!*cookie) {
		emit_ip_error_event(skb, 0, cookie, false, 0, send + 1, 0, IP_ERROR_INET_NO_COOKIE);
		return;
	}

	if (skb_load_bytes(skb, 0, &ip, sizeof(struct iphdr)) < 0) {
		emit_ip_error_event(skb, 0, cookie, false, 0, send + 1, 0, IP_ERROR_INET_READ_VER);
		return;
	}

	val = (struct msg_icmp_event *)map_lookup_elem(&icmp_event_heap, &zero);
	if (!val)
		return;

	val->tuple.send = send;
	val->icmp_ip_port = 0;
	val->icmp_ip_proto = 0;
	val->icmp_ip_ttl = 0;
	val->icmp_ip_pointer = 0;
	val->icmp_gateway[0] = 0;
	val->icmp_gateway[1] = 0;

	switch (ip.version) {
	case 4:
		if (ip.protocol != IPPROTO_ICMP)
			return;

		if (skb_load_bytes(skb, ip.ihl * 4, icmp_data, sizeof(icmp_data)) < 0) {
			emit_ip_error_event(skb, &ip, cookie, false, ip.version, send + 1, 0, IP_ERROR_INET_READ_PAYLOAD);
			return;
		}

		val->icmp_type = icmp_data[0];
		// Only handle Echo / Echo Reply at this point.
		if (val->icmp_type != ICMP_ECHO && val->icmp_type != ICMP_ECHOREPLY)
			return;
		val->icmp_code = icmp_data[1];
		val->common.op = ISO_MSG_OP_ICMP;
		val->icmp_len = bpf_ntohs(ip.tot_len) - (ip.ihl * 4) - ICMP_HDR_LEN; // total len - IP header - ICMP header
		*(u32 *)val->icmp_data = *(u32 *)(icmp_data + ICMP_HDR_DATA_OFF);

		if (send) {
			val->tuple.saddr[0] = ip.saddr;
			val->tuple.daddr[0] = ip.daddr;
		} else {
			val->tuple.saddr[0] = ip.daddr;
			val->tuple.daddr[0] = ip.saddr;
		}
		val->tuple.saddr[1] = 0;
		val->tuple.daddr[1] = 0;
		val->tuple.ipv6 = 0;
		val->tuple.proto = IPPROTO_ICMP;

		send_icmp_event(skb, val, cookie);
		break;
	case 6:
		break;
	default:
		emit_ip_error_event(skb, 0, cookie, false, ip.version, send + 1, 0, IP_ERROR_INET_NO_VERSION);
		return;
	}
}

static inline __attribute__((always_inline)) void
icmp_handler(struct __sk_buff *skb, bool send)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (long *)(long)skb->data;
	struct msg_icmp_event *val;
	struct iphdr *ip;
	u8 *icmp_data;
	int zero = 0;
	u64 cookie;

	write_cookie(&cookie, (u64)skb->sk);

	if (data + 1 > data_end) {
		emit_ip_error_event(skb, 0, &cookie, false, 0, send + 1, 0, IP_ERROR_INET_READ_VER);
		return;
	}

	val = (struct msg_icmp_event *)map_lookup_elem(&icmp_event_heap, &zero);
	if (!val)
		return;

	val->tuple.send = send;
	val->icmp_ip_port = 0;
	val->icmp_ip_proto = 0;
	val->icmp_ip_ttl = 0;
	val->icmp_ip_pointer = 0;
	val->icmp_gateway[0] = 0;
	val->icmp_gateway[1] = 0;

	ip = (struct iphdr *)data;
	switch (ip->version) {
	case 4:
		if (data + sizeof(struct iphdr) > data_end) {
			emit_ip_error_event(skb, 0, &cookie, false, ip->version, send + 1, 0, IP_ERROR_INET_READ_IP);
			return;
		}
		if (ip->protocol != IPPROTO_ICMP)
			return;

		if (data + (ip->ihl * 4) + ICMP_HDR_LEN > data_end) {
			emit_ip_error_event(skb, ip, &cookie, false, ip->version, send + 1, 0, IP_ERROR_INET_READ_PAYLOAD);
			return;
		}
		icmp_data = (u8 *)data + (ip->ihl * 4);
		val->icmp_type = icmp_data[0];
		// Only handle Echo / Echo Reply at this point.
		if (val->icmp_type != ICMP_ECHO && val->icmp_type != ICMP_ECHOREPLY)
			return;
		val->icmp_code = icmp_data[1];
		val->common.op = ISO_MSG_OP_ICMP;
		val->icmp_len = bpf_ntohs(ip->tot_len) - (ip->ihl * 4) - ICMP_HDR_LEN; // total len - IP header - ICMP header
		*(u32 *)val->icmp_data = *(u32 *)(icmp_data + ICMP_HDR_DATA_OFF);

		if (send) {
			val->tuple.saddr[0] = ip->saddr;
			val->tuple.daddr[0] = ip->daddr;
		} else {
			val->tuple.saddr[0] = ip->daddr;
			val->tuple.daddr[0] = ip->saddr;
		}
		val->tuple.saddr[1] = 0;
		val->tuple.daddr[1] = 0;
		val->tuple.ipv6 = 0;
		val->tuple.proto = IPPROTO_ICMP;

		send_icmp_event(skb, val, &cookie);
		break;
	case 6:
		break;
	default:
		emit_ip_error_event(skb, 0, &cookie, false, ip->version, send + 1, 0, IP_ERROR_INET_NO_VERSION);
		return;
	}
}

#endif //__BPF_ICMP_H_
