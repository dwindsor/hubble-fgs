#ifndef __BPF_INET_H_
#define __BPF_INET_H_

#include "api.h"
#include "hubble_msg.h"
#include "bpf_events.h"
#include "bpf_udp.h"
#include "bpf_burst_process.h"
#include "cookie.h"
#include "bpf_network_helpers.h"

static inline __attribute__((always_inline)) u8 ip_payload_off(struct iphdr *ip)
{
	u8 ip_off;

	ip_off = ip->ihl;
	ip_off &= 0x0f;
	ip_off *= 4;
	return ip_off;
}

static inline __attribute__((always_inline)) struct udp_info *
udp_info(struct iphdr *ip, bool ipv6, struct udphdr *udp, bool send)
{
	struct udp_info *info;
	int zero = 0;

	info = map_lookup_elem(&udp_info_heap, &zero);
	if (!info || !ip)
		return 0;

	if (send) {
		if (!ipv6) {
			info->saddr.ipv4 = ip->saddr;
			info->daddr.ipv4 = ip->daddr;
			info->ipv6 = false;
		} else {
			copy_ipv6_addrs_to_info(info,
						&((struct ipv6hdr *)ip)->saddr,
						&((struct ipv6hdr *)ip)->daddr);
			info->ipv6 = true;
		}
		info->sport = bpf_ntohs(udp->source);
		info->dport = udp->dest;
	} else {
		if (!ipv6) {
			info->saddr.ipv4 = ip->daddr;
			info->daddr.ipv4 = ip->saddr;
			info->ipv6 = false;
		} else {
			copy_ipv6_addrs_to_info(info,
						&((struct ipv6hdr *)ip)->daddr,
						&((struct ipv6hdr *)ip)->saddr);
			info->ipv6 = true;
		}
		info->sport = bpf_ntohs(udp->dest);
		info->dport = udp->source;
	}
	info->padding[0] = 0;
	info->padding[1] = 0;
	info->padding[2] = 0;
	return info;
}

static inline __attribute__((always_inline)) struct udp_info *
udp_port_info(struct udphdr *udp, bool send)
{
	struct udp_info *info;
	int zero = 0;

	info = map_lookup_elem(&udp_info_heap, &zero);
	if (!info)
		return 0;

	if (send) {
		info->sport = bpf_ntohs(udp->source);
		info->dport = udp->dest;
	} else {
		info->sport = bpf_ntohs(udp->dest);
		info->dport = udp->source;
	}
	info->padding[0] = 0;
	info->padding[1] = 0;
	info->padding[2] = 0;
	return info;
}

/* This logic is a bit racy, but we can handle it. Thinking through the
 * cases. Multiple sends may happen concurrently on the same key. If
 * the key is not in the map we may have multiple cores in the !value
 * branch. This is OK as long as the user space is aware this may happen.
 * In this case user space will see duplicate 'connect' events and
 * metrics will correctly aggreagate them. One of these connects will
 * win the map_update_elem race. And any future lookups from BPF side
 * will be additive on that event. The value branch must be slightly
 * careful with pkt/byte couonter updates to ensure concurrent update
 * on the value are handled, we use __fetch_and_adds here for this to
 * be safe. And the only remaining ugly bit is ktime can't be trusted.
 * If more than one core is writing into ktime we may corrupt it. So
 * we need a WRITE_ONCE to ensure the compiler does this in a single
 * store. Then we get a coherent ktime although we don't know what
 * core its from. We don't really care though as long as its
 * approximately accurate which it will be or we wouldn't have
 * concurrent cores here.
 *
 * To accomodate older kernels that do not have cookie set we use the
 * address of the sock as the cookie. This should be unique and consistent
 * for the life of the socket, but we run into problems if a sock is
 * reused. We handle this by monitoring sock creation and updating our
 * maps.
 * 
 * The process is populated by looking up the cookie/sock in the
 * socket_map.
 */
static inline __attribute__((always_inline)) struct udp_info_value *
__udp_send(struct __sk_buff *skb, struct udp_info **info, u64 *cookie,
	   struct iphdr *ip, bool ipv6, struct udphdr *udp, int payload_sz,
	   bool send, bool lazy)
{
	struct udp_info_value *value;
	struct socketmap_value *process;
	int zero = 0;

	value = map_lookup_elem(&udp_map, cookie);
	process = locate_socketmap(cookie, (struct sock *)skb->sk, lazy);

	if (!value) {
		value = map_lookup_elem(&udp_value_heap, &zero);
		if (!value)
			return 0;

		if (send)
			udp_info_tx_reset(value, payload_sz);
		else
			udp_info_rx_reset(value, payload_sz);

		/* Store the info in the entry for later use,
		 * and potentially for searching from userland
		 * in case we ever need to locate a socket */
		*info = udp_info(ip, ipv6, udp, send);
		if (!*info)
			return 0;
		if (!ipv6) {
			set_ipv6_addr_from_ipv4(value->saddr,
						(*info)->saddr.ipv4);
			set_ipv6_addr_from_ipv4(value->daddr,
						(*info)->daddr.ipv4);
			value->ipv6 = false;
		} else {
			copy_ipv6_addr(value->saddr, (*info)->saddr.ipv6);
			copy_ipv6_addr(value->daddr, (*info)->daddr.ipv6);
			value->ipv6 = true;
		}
		value->sport = (*info)->sport;
		value->dport = (*info)->dport;
		value->skb_consume_misses = 0;

		/* If process was found, fill in the PID */
		if (process) {
			value->pid = process->key.pid;
			value->pid_ktime = process->key.ktime;
		} else {
			value->pid = 0;
		}

		if (value->pid)
			emit_udp_connect_event(skb, value);
		map_update_elem(&udp_map, cookie, value, 0);
	} else if (process && value->pid != process->key.pid) {
		/* PID doesn't match, so this must be a new socket */
		if (send)
			udp_info_tx_reset(value, payload_sz);
		else
			udp_info_rx_reset(value, payload_sz);
		*info = udp_info(ip, ipv6, udp, send);
		if (!*info)
			return 0;
		if (!ipv6) {
			set_ipv6_addr_from_ipv4(value->saddr,
						(*info)->saddr.ipv4);
			set_ipv6_addr_from_ipv4(value->daddr,
						(*info)->daddr.ipv4);
			value->ipv6 = false;
		} else {
			copy_ipv6_addr(value->saddr, (*info)->saddr.ipv6);
			copy_ipv6_addr(value->daddr, (*info)->daddr.ipv6);
			value->ipv6 = true;
		}
		value->sport = (*info)->sport;
		value->dport = (*info)->dport;
		value->skb_consume_misses = 0;
		value->pid = process->key.pid;
		value->pid_ktime = process->key.ktime;

		emit_udp_connect_event(skb, value);
	} else {
		if (send)
			update_tx_value(value, payload_sz);
		else
			update_rx_value(value, payload_sz);
	}
	return value;
}

/* Lazy versions of udp send do not support copying the payload to
 * user land, as this isn't provided by older kernels.
 * We take a boolean, dns, to specify if we are sending DNS payloads
 * to userland. The reason we need this rather than a simple lookup
 * on config->dnsPorts[0] is to force clang to exclude the DNS code
 * because it contains a call to skb_load_bytes() which we can't have
 * on the kprobe solution for older kernels.
 */
static inline __attribute__((always_inline)) int
udp_send(struct __sk_buff *skb, void *skb_head, struct iphdr *ip, bool ipv6,
	 struct udphdr *udp, u64 *cookie, int payload_off, int payload_sz,
	 bool send, bool lazy, bool kp)
{
	struct udp_info_value *value;
	struct udp_info *info = 0;
	struct udp_sensor_config *config;
	int zero = 0;

	value = __udp_send(skb, &info, cookie, ip, ipv6, udp, payload_sz, send,
			   lazy);
	if (!value)
		return 1;

	config = map_lookup_elem(&udp_config_map, &zero);
	if (!config)
		return 1;

	if (config->dnsPorts[0] != 0) {
		/* info may have been filled in for us by __udp_send() */
		if (!info) {
			info = udp_port_info(udp, send);
			if (!info)
				return 1;
		}
		if (dns_port_match(config->dnsPorts, info->sport,
				   bpf_ntohs(info->dport))) {
			if (!lazy && value->pid) {
				/* We subtract 1 from payload_sz because we need to +1 it
				 * later to sat verifier constraint that skb_load_bytes
				 * must be nonzero.
				 */
				emit_udp_payload_event(skb, value, payload_off,
						       payload_sz - 1);
			} else {
				/* The PID is empty because we couldn't look up
				 * the process in the cookie->process map. We
				 * therefore store it for the API-level function
				 * (either udp_sendret or udp_recv) to add
				 * process information and then transmit it.
				 * We also use this store-and-act-later approach
				 * for kernels <5.10.
				 */

				// Check payload offset is valid.
				if (payload_off != -1)
					store_udp_payload_event(skb, skb_head,
								cookie, value,
								payload_off,
								payload_sz - 1,
								kp);
			}
		}
	}
	return 1;
}

static inline __attribute__((always_inline)) void
udp_burst(void *ctx, u64 *cookie, int vol, u64 send)
{
	struct udp_sensor_config *config;
	struct process_network_burst_config *c;
	struct socketmap_value *process;
	int zero = 0;

	config = map_lookup_elem(&udp_config_map, &zero);
	if (!config || !config->watermark_enable)
		return;

	c = map_lookup_elem(&pn_burst_config_heap, &zero);
	if (!c)
		return;
	c->avg_window_size_ms = config->watermark_avg_window_size_ms;
	c->window_size = config->watermark_window_size;
	c->trigger_mult = config->watermark_trigger_percent;

	process = lookup_socketmap(cookie);
	/* If we don't have a process then we can't assign the burst information
	 * to it, and there is little else we can do.
	 * Additionally, if the sk address had previously been mapped to the
	 * process and kernel >=5.10, then it would have been remapped from
	 * the socket cookie by __udp_send() already.
	 */
	if (!process || !process->key.pid)
		return;

	process_network_burst(ctx, process, IPPROTO_UDP, send, vol, c);
}

static inline __attribute__((always_inline)) void
inet_handler_lazy(struct __sk_buff *skb, bool send)
{
	struct udp_packet_details *packet;
	u64 *cookie;
	int zero = 0;
	u8 proto;
	unsigned long int err = 0;

	cookie = map_lookup_elem(&udp_cookie_heap, &zero);
	if (!cookie)
		return;
	write_cookie_from_sk(cookie, (struct sock *)skb->sk, true);
	if (!*cookie)
		return;

	packet = map_lookup_elem(&udp_header_heap, &zero);
	if (!packet)
		return;

	if (skb_load_bytes(skb, 0, &packet->ip, sizeof(struct iphdr)) < 0)
		return;

	switch (packet->ip.ip4.version) {
	case 4:
		if (packet->ip.ip4.protocol != IPPROTO_UDP)
			return;
		packet->ipv6 = false;
		packet->udp_off = ip_payload_off(&packet->ip.ip4);
		break;
	case 6:
		if (skb_load_bytes(skb, 0, &packet->ip,
				   sizeof(struct ipv6hdr)) < 0)
			return;
		packet->ipv6 = true;
		proto = get_ip6_proto(&packet->udp_off, &packet->ip.ip6, 0, skb,
				      0, true, false, &err);
		if (proto == IP_HEADER_ERROR) {
			emit_ip_error_event(skb, &packet->ip.ip6, cookie, true,
					    err);
			return;
		} else if (proto != IPPROTO_UDP) {
			return;
		}
		if (!packet->udp_off)
			return;
		break;
	default:
		return;
	}
	if (skb_load_bytes(skb, packet->udp_off, &packet->udp,
			   sizeof(struct udphdr)) < 0)
		return;
	packet->payload_sz = bpf_ntohs(packet->udp.len) - sizeof(struct udphdr);
	packet->payload_off = packet->udp_off + sizeof(struct udphdr);
	udp_send(skb, 0, &packet->ip.ip4, packet->ipv6, &packet->udp, cookie,
		 packet->payload_off, packet->payload_sz, send, true, false);
	udp_burst(skb, cookie, packet->payload_sz, send);
}

static inline __attribute__((always_inline)) void
inet_handler_lazy_kp(void *ctx, struct sock *sk, struct sk_buff *skb, bool send)
{
	struct udp_packet_details *packet;
	int zero = 0;
	u64 cookie;
	u8 proto;
	unsigned long int err = 0;

	cookie = (u64)sk;
	if (!cookie)
		return;
	packet = map_lookup_elem(&udp_header_heap, &zero);
	if (!packet)
		return;

	packet->version = get_ip_version(&packet->network_header_off,
					 &packet->skb_head, skb);
	switch (packet->version) {
	case 4:
		if (!get_ip4_header(&packet->ip.ip4, packet->network_header_off,
				    packet->skb_head))
			return;
		packet->ipv6 = false;
		if (packet->ip.ip4.protocol != IPPROTO_UDP)
			return;
		if (!get_udp_header(&packet->udp, &packet->payload_off,
				    packet->skb_head, skb))
			return;
		break;
	case 6:
		if (!get_ip6_header(&packet->ip.ip6, packet->network_header_off,
				    packet->skb_head))
			return;
		packet->ipv6 = true;
		proto = get_ip6_proto(0, &packet->ip.ip6,
				      packet->network_header_off,
				      packet->skb_head, 0, true, true, &err);
		if (proto == IP_HEADER_ERROR) {
			emit_ip_error_event(ctx, &packet->ip.ip6, &cookie, true,
					    err);
			return;
		} else if (proto != IPPROTO_UDP) {
			return;
		}
		if (!get_udp_header(&packet->udp, &packet->payload_off,
				    packet->skb_head, skb))
			return;
		break;
	default:
		return;
	}

	// skb might be non-linear (skb->data_len > 0). If so, we need to do more
	// work to access and process the payload. Because it is very difficult to
	// access payload data in non-linear skbs, disable DNS parsing for this
	// program entirely, affecting kernels 4.19 < 5.4.
	// Rationale is that we shouldn't ship a half-working solution. If we need
	// to support this in the future, then potential solutions will be logged
	// in a suitable issue.
	packet->payload_off = -1;

	packet->payload_sz = bpf_ntohs(packet->udp.len) - sizeof(struct udphdr);
	udp_send(ctx, packet->skb_head, &packet->ip.ip4, packet->ipv6,
		 &packet->udp, &cookie, packet->payload_off, packet->payload_sz,
		 send, true, true);
	udp_burst(ctx, &cookie, packet->payload_sz, send);
}

static inline __attribute__((always_inline)) void
inet_handler(struct __sk_buff *skb, bool send)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (long *)(long)skb->data;
	struct iphdr *ip;
	struct udphdr *udp;
	struct udp_packet_details *packet;
	int zero = 0;
	u64 cookie;
	u8 proto;
	unsigned long int err = 0;

	cookie = get_socket_cookie(skb);
	packet = map_lookup_elem(&udp_header_heap, &zero);
	if (!packet)
		return;

	if (data + 1 > data_end)
		return;

	ip = (struct iphdr *)data;

	switch (ip->version) {
	case 4:
		if (data + sizeof(struct iphdr) > data_end)
			return;
		if (ip->protocol != IPPROTO_UDP)
			return;
		packet->udp_off = ip_payload_off(ip);
		udp = (struct udphdr *)(data + packet->udp_off);
		if (data + packet->udp_off + sizeof(struct udphdr) > data_end)
			return;
		packet->payload_sz =
			bpf_ntohs(udp->len) - sizeof(struct udphdr);
		packet->payload_off = packet->udp_off + sizeof(struct udphdr);
		udp_send(skb, 0, ip, false, udp, &cookie, packet->payload_off,
			 packet->payload_sz, send, false, false);
		break;
	case 6:
		if (data + sizeof(struct ipv6hdr) > data_end)
			return;
		proto = get_ip6_proto(&packet->udp_off, (struct ipv6hdr *)ip, 0,
				      data, data_end, false, false, &err);
		if (proto == IP_HEADER_ERROR) {
			emit_ip_error_event(skb, (struct ipv6hdr *)ip, &cookie,
					    true, err);
			return;
		} else if (proto != IPPROTO_UDP) {
			return;
		}
		if (!packet->udp_off)
			return;
		udp = (struct udphdr *)(data + packet->udp_off);
		if (data + packet->udp_off + sizeof(struct udphdr) > data_end)
			return;
		packet->payload_sz =
			bpf_ntohs(udp->len) - sizeof(struct udphdr);
		packet->payload_off = packet->udp_off + sizeof(struct udphdr);
		udp_send(skb, 0, ip, true, udp, &cookie, packet->payload_off,
			 packet->payload_sz, send, false, false);
		break;
	default:
		return;
	}

	udp_burst(skb, &cookie, packet->payload_sz, send);
}

#endif //__BPF_INET_H_
