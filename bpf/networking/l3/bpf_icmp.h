#ifndef __BPF_ICMP_H_
#define __BPF_ICMP_H_

#include "vmlinux.h"
#include "api.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "../cookie.h"
#include "../bpf_network_helpers.h"
#include "../lib/address_family.h"
#include "../lib/config.h"

#define ICMP_HDR_LEN	  4
#define ICMP_HDR_DATA_OFF 4

// Taken from include/uapi/linux/icmp.h
#define ICMP_ECHOREPLY	    0 /* Echo Reply			*/
#define ICMP_DEST_UNREACH   3 /* Destination Unreachable	*/
#define ICMP_SOURCE_QUENCH  4 /* Source Quench		*/
#define ICMP_REDIRECT	    5 /* Redirect (change route)	*/
#define ICMP_ECHO	    8 /* Echo Request			*/
#define ICMP_TIME_EXCEEDED  11 /* Time Exceeded		*/
#define ICMP_PARAMETERPROB  12 /* Parameter Problem		*/
#define ICMP_TIMESTAMP	    13 /* Timestamp Request		*/
#define ICMP_TIMESTAMPREPLY 14 /* Timestamp Reply		*/
#define ICMP_INFO_REQUEST   15 /* Information Request		*/
#define ICMP_INFO_REPLY	    16 /* Information Reply		*/
#define ICMP_ADDRESS	    17 /* Address Mask Request		*/
#define ICMP_ADDRESSREPLY   18 /* Address Mask Reply		*/

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

#define IPSKB_L3SLAVE (1 << 7)

static inline __attribute__((always_inline)) int
inet_sdif(struct sk_buff *skb)
{
	struct netns_ipv4___with_l3mdev *ipv4;
	struct inet_skb_parm *ipcb;
	struct net *net = 0;
	__u16 flags;
	int iif;

	ipv4 = (struct netns_ipv4___with_l3mdev *)&net->ipv4;
	if (!bpf_core_field_exists(ipv4->sysctl_raw_l3mdev_accept))
		return 0;

	ipcb = (struct inet_skb_parm *)_(&(skb->cb));
	probe_read_kernel(&flags, sizeof(flags), _(&(ipcb->flags)));
	if (flags & IPSKB_L3SLAVE) {
		probe_read_kernel(&iif, sizeof(iif), _(&(ipcb->iif)));
		return iif;
	}
	return 0;
}

static inline __attribute__((always_inline)) void
send_icmp_event(void *ctx, struct msg_icmp_event *val, u64 *cookie, struct sk_buff *skb, void *reported_datagram)
{
	struct socketmap_value *process = 0;
	struct socket_tuple_key *key;
	struct net_device *dev;
	u64 *new_cookie;
	int dif, sdif;

	if (*cookie)
		process = lookup_socketmap(cookie);
	if (!process && icmp_tracking_enabled() && skb && reported_datagram) {
		key = make_tuple_key_from_skb(skb, val, reported_datagram);
		if (key) {
			probe_read_kernel(&dev, sizeof(dev), _(&(skb->dev)));
			probe_read_kernel(&dif, sizeof(dif), _(&(dev->ifindex)));
			sdif = inet_sdif(skb);
			new_cookie = lookup_socket_tuple_map(key, dif, sdif);
			if (new_cookie && *new_cookie)
				process = lookup_socketmap(new_cookie);
		}
	}
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
	u8 icmp_data[ICMP_HDR_LEN * 2];
	struct msg_icmp_event *val;
	struct iphdr rep_ip4;
	struct tcphdr tcp;
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

		if (skb_load_bytes(skb, ip.ihl * sizeof(u32), icmp_data, sizeof(icmp_data)) < 0) {
			emit_ip_error_event(skb, &ip, cookie, false, ip.version, send + 1, 0, IP_ERROR_INET_READ_PAYLOAD);
			return;
		}

		val->icmp_type = icmp_data[0];
		val->icmp_code = icmp_data[1];
		val->common.op = ISO_MSG_OP_ICMP;
		val->icmp_len = bpf_ntohs(ip.tot_len) - (ip.ihl * sizeof(u32)) - ICMP_HDR_LEN - sizeof(u32); // total len - IP header - ICMP header
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

		if (skb_load_bytes(skb, (ip.ihl * sizeof(u32)) + sizeof(icmp_data), &rep_ip4, sizeof(rep_ip4)) == 0) {
			val->icmp_ip_proto = rep_ip4.protocol;
			switch (val->icmp_type) {
			case ICMP_DEST_UNREACH:
			case ICMP_TIME_EXCEEDED:
			case ICMP_PARAMETERPROB:
			case ICMP_SOURCE_QUENCH:
			case ICMP_REDIRECT:
				val->icmp_ip_ttl = rep_ip4.ttl;

				switch (val->icmp_ip_proto) {
				case IPPROTO_TCP:
				case IPPROTO_UDP: // Note ports are in the same location in TCP and UDP headers
					if (skb_load_bytes(skb, (ip.ihl * sizeof(u32)) + sizeof(icmp_data) + sizeof(rep_ip4), &tcp, sizeof(tcp)) == 0)
						val->icmp_ip_port = bpf_ntohs(tcp.dest);
					break;
				}
				break;
			}
		}
		if (val->icmp_type == ICMP_PARAMETERPROB)
			val->icmp_ip_pointer = val->icmp_data[0];
		if (val->icmp_type == ICMP_REDIRECT)
			val->icmp_gateway[0] = *(__u32 *)(val->icmp_data);

		send_icmp_event(skb, val, cookie, 0, 0);
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
	struct iphdr *rep_ip4;
	struct tcphdr *tcp;
	struct iphdr *ip;
	u8 *icmp_data;
	int zero = 0;
	u8 *rep_ptr;
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

		if (data + (ip->ihl * sizeof(u32)) + ICMP_HDR_LEN + sizeof(u32) > data_end) {
			emit_ip_error_event(skb, ip, &cookie, false, ip->version, send + 1, 0, IP_ERROR_INET_READ_PAYLOAD);
			return;
		}
		icmp_data = (u8 *)data + (ip->ihl * sizeof(u32));
		val->icmp_type = icmp_data[0];
		val->icmp_code = icmp_data[1];
		val->common.op = ISO_MSG_OP_ICMP;
		val->icmp_len = bpf_ntohs(ip->tot_len) - (ip->ihl * sizeof(u32)) - ICMP_HDR_LEN - sizeof(u32); // total len - IP header - ICMP header
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

		if (icmp_data + ICMP_HDR_LEN + sizeof(u32) + sizeof(struct iphdr) <= data_end) {
			rep_ptr = icmp_data + ICMP_HDR_LEN + sizeof(u32);
			rep_ip4 = (struct iphdr *)rep_ptr;
			val->icmp_ip_proto = rep_ip4->protocol;

			switch (val->icmp_type) {
			case ICMP_DEST_UNREACH:
			case ICMP_TIME_EXCEEDED:
			case ICMP_PARAMETERPROB:
			case ICMP_SOURCE_QUENCH:
			case ICMP_REDIRECT:
				val->icmp_ip_ttl = rep_ip4->ttl;

				switch (val->icmp_ip_proto) {
				case IPPROTO_TCP:
				case IPPROTO_UDP: // Note ports are in the same location in TCP and UDP headers
					tcp = (struct tcphdr *)(rep_ptr + (rep_ip4->ihl * sizeof(u32)));
					if (tcp + sizeof(struct tcphdr) > data_end)
						break;
					val->icmp_ip_port = tcp->dest;
					break;
				}
				break;
			}
		}
		if (val->icmp_type == ICMP_PARAMETERPROB)
			val->icmp_ip_pointer = val->icmp_data[0];
		if (val->icmp_type == ICMP_REDIRECT)
			val->icmp_gateway[0] = *(__u32 *)(val->icmp_data);

		send_icmp_event(skb, val, &cookie, 0, 0);
		break;
	case 6:
		break;
	default:
		emit_ip_error_event(skb, 0, &cookie, false, ip->version, send + 1, 0, IP_ERROR_INET_NO_VERSION);
		return;
	}
}

#endif //__BPF_ICMP_H_
