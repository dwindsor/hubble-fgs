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
udp4_info(struct iphdr *ip, struct udphdr *udp, bool send)
{
	struct udp_info *info;
	int zero = 0;

	info = map_lookup_elem(&udp_info_heap, &zero);
	if (!info)
		return 0;

	if (send) {
		info->saddr = ip->saddr;
		info->daddr = ip->daddr;
		info->sport = bpf_ntohs(udp->source);
		info->dport = udp->dest;
	} else {
		info->saddr = ip->daddr;
		info->daddr = ip->saddr;
		info->sport = bpf_ntohs(udp->dest);
		info->dport = udp->source;
	}
	info->padding = 0;
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
 * socket_cookie_to_proc_map.
 */
static inline __attribute__((always_inline)) struct udp_info_value *
__udp4_send(struct __sk_buff *skb, struct udp_info **info, u64 *cookie,
	    struct iphdr *ip, struct udphdr *udp, int payload_sz, bool send,
	    bool lazy)
{
	struct udp_info_value *value;
	struct execve_map_value *process;
	int zero = 0;
	u64 sk_cookie;

	value = map_lookup_elem(&udp_map, cookie);
	process = map_lookup_elem(&socket_cookie_to_proc_map, cookie);
	if (!process && !lazy) {
		sk_cookie = (u64)skb->sk;
		process =
			map_lookup_elem(&socket_cookie_to_proc_map, &sk_cookie);
		if (process) {
			map_update_elem(&socket_cookie_to_proc_map, cookie,
					process, 0);
			map_delete_elem(&socket_cookie_to_proc_map, &sk_cookie);
		}
	}

	if (!value) {
		value = map_lookup_elem(&udp_value_heap, &zero);
		if (!value)
			return 0;

		if (send)
			udp_info_tx_reset(value, payload_sz);
		else
			udp_info_rx_reset(value, payload_sz);

		value->skb_consume_misses = 0;

		/* If process was found, fill in the PID */
		if (process) {
			value->pid = process->key.pid;
			value->pid_ktime = process->key.ktime;
		} else {
			value->pid = 0;
		}

		/* Fill in the tuple */
		*info = udp4_info(ip, udp, send);
		if (*info) {
			value->saddr = (*info)->saddr;
			value->daddr = (*info)->daddr;
			value->sport = (*info)->sport;
			value->dport = (*info)->dport;
			if (value->pid != 0) {
				emit_udp_connect_event(skb, value);
			}
		}

		map_update_elem(&udp_map, cookie, value, 0);
	} else if (process && value->pid != process->key.pid) {
		/* PID doesn't match, so this must be a new socket */
		if (send)
			udp_info_tx_reset(value, payload_sz);
		else
			udp_info_rx_reset(value, payload_sz);

		value->skb_consume_misses = 0;
		value->pid = process->key.pid;
		value->pid_ktime = process->key.ktime;

		/* Fill in the tuple */
		*info = udp4_info(ip, udp, send);
		if (*info) {
			value->saddr = (*info)->saddr;
			value->daddr = (*info)->daddr;
			value->sport = (*info)->sport;
			value->dport = (*info)->dport;
			emit_udp_connect_event(skb, value);
		}
	} else {
		/* Existing entry */
		if (send)
			update_tx_value(value, payload_sz);
		else
			update_rx_value(value, payload_sz);

		if (value->saddr == 0) {
			/* Fill in the tuple */
			*info = udp4_info(ip, udp, send);
			if (*info) {
				value->saddr = (*info)->saddr;
				value->daddr = (*info)->daddr;
				value->sport = (*info)->sport;
				value->dport = (*info)->dport;
				emit_udp_connect_event(skb, value);
			}
		}
	}
	return value;
}

/* Lazy versions of udp4 send do not support copying the payload to
 * user land, as this isn't provided by older kernels.
 * We take a boolean, dns, to specify if we are sending DNS payloads
 * to userland. The reason we need this rather than a simple lookup
 * on config->dnsPorts[0] is to force clang to exclude the DNS code
 * because it contains a call to skb_load_bytes() which we can't have
 * on the kprobe solution for older kernels.
 */
static inline __attribute__((always_inline)) int
udp4_send(struct __sk_buff *skb, void *skb_head, struct iphdr *ip,
	  struct udphdr *udp, u64 *cookie, int payload_off, int payload_sz,
	  bool send, bool lazy, bool kp)
{
	struct udp_info_value *value;
	struct udp_info *info = 0;
	struct udp_sensor_config *config;
	int zero = 0;

	value = __udp4_send(skb, &info, cookie, ip, udp, payload_sz, send,
			    lazy);
	if (!value)
		return 1;

	config = map_lookup_elem(&udp_config_map, &zero);
	if (!config)
		return 1;

	if (config->dnsPorts[0] != 0) {
		/* info may have been filled in for us by __udp4_send() */
		if (!info) {
			info = udp4_info(ip, udp, send);
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
				 * (either udp4_sendret or udp4_recvret) to add
				 * process information and then transmit it.
				 * We also use this store-and-act-later approach
				 * for kernels <5.10.
				 */
				store_udp_payload_event(skb, skb_head, cookie,
							value, payload_off,
							payload_sz - 1, kp);
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
	struct execve_map_value *process;
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

	process = map_lookup_elem(&socket_cookie_to_proc_map, cookie);
	/* If we don't have a process then we can't assign the burst information
	 * to it, and there is little else we can do.
	 * Additionally, if the sk address had previously been mapped to the
	 * process and kernel >=5.10, then it would have been remapped from
	 * the socket cookie by __udp4_send() already.
	 */
	if (!process)
		return;

	process_network_burst(ctx, process, IPPROTO_UDP, send, vol, c);
}

static inline __attribute__((always_inline)) void
inet_handler_lazy(struct __sk_buff *skb, bool send)
{
	struct udp_packet_details *packet;
	u8 udp_off;
	u64 *cookie;
	int zero = 0;

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

	if (packet->ip.protocol == IPPROTO_UDP) {
		udp_off = ip_payload_off(&packet->ip);
		if (skb_load_bytes(skb, udp_off, &packet->udp,
				   sizeof(struct udphdr)) < 0)
			return;
		packet->payload_sz =
			bpf_ntohs(packet->udp.len) - sizeof(struct udphdr);
		packet->payload_off = udp_off + sizeof(struct udphdr);
		udp4_send(skb, 0, &packet->ip, &packet->udp, cookie,
			  packet->payload_off, packet->payload_sz, send, true,
			  false);
		udp_burst(skb, cookie, packet->payload_sz, send);
	}
	return;
}

static inline __attribute__((always_inline)) void
inet_handler_lazy_kp(void *ctx, struct sock *sk, struct sk_buff *skb, bool send)
{
	struct udp_packet_details *packet;
	int zero = 0;
	u64 cookie;

	cookie = (u64)sk;
	if (!cookie)
		return;
	packet = map_lookup_elem(&udp_header_heap, &zero);
	if (!packet)
		return;

	if (!get_ip4_header(&packet->ip, &packet->skb_head, skb))
		return;

	if (packet->ip.protocol == IPPROTO_UDP) {
		if (!get_udp4_header(&packet->udp, &packet->payload_off,
				     packet->skb_head, skb))
			return;
		packet->payload_sz =
			bpf_ntohs(packet->udp.len) - sizeof(struct udphdr);
		udp4_send(ctx, packet->skb_head, &packet->ip, &packet->udp,
			  &cookie, packet->payload_off, packet->payload_sz,
			  send, true, true);
		udp_burst(ctx, &cookie, packet->payload_sz, send);
	}
	return;
}

static inline __attribute__((always_inline)) void
inet_handler(struct __sk_buff *skb, bool send)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (long *)(long)skb->data;
	struct iphdr *ip;
	struct udphdr *udp;
	u8 udp_off;
	u64 cookie;
	int payload_sz;
	int payload_off;

	cookie = get_socket_cookie(skb);
	if (data + sizeof(struct iphdr) > data_end)
		return;
	ip = (struct iphdr *)data;

	if (ip->protocol == IPPROTO_UDP) {
		udp_off = ip_payload_off(ip);
		udp = (struct udphdr *)(data + udp_off);
		if (data + udp_off + sizeof(*udp) > data_end)
			return;
		payload_sz = bpf_ntohs(udp->len) - sizeof(struct udphdr);
		payload_off = udp_off + sizeof(struct udphdr);
		udp4_send(skb, 0, ip, udp, &cookie, payload_off, payload_sz,
			  send, false, false);
		udp_burst(skb, &cookie, payload_sz, send);
	}
	return;
}

#endif //__BPF_INET_H_
