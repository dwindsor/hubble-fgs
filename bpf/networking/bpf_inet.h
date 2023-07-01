#ifndef __BPF_INET_H_
#define __BPF_INET_H_

#include "vmlinux.h"
#include "api.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "bpf_udp.h"
#include "bpf_latency.h"
#include "bpf_process_network_watermarks.h"
#include "cookie.h"
#include "bpf_network_helpers.h"
#include "bpf_udp_seq_error.h"
#include "address_family.h"
#include "bpf_tracing.h"

static inline __attribute__((always_inline)) u8 ip_payload_off(struct iphdr *ip)
{
	u8 ip_off;

	ip_off = ip->ihl;
	ip_off &= 0x0f;
	ip_off *= 4;
	return ip_off;
}

static inline __attribute__((always_inline)) struct udp_info *
udp_info(struct iphdr *ip, bool ipv6, struct udphdr *udp, u64 send)
{
	struct udp_info *info;
	int zero = 0;

	info = (struct udp_info *)map_lookup_elem(&tg_udp_info_heap, &zero);
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

static inline __attribute__((always_inline)) void
udp_key(struct udp_info_key *key, struct iphdr *ip, bool ipv6, struct udphdr *udp, u64 send)
{
	if (send) {
		if (!ipv6) {
			key->daddr[0] = ip->daddr;
			key->daddr[1] = 0;
			key->ipv6 = false;
		} else {
			u64 *addr = (u64 *)&((struct ipv6hdr *)ip)->daddr;
			key->daddr[0] = addr[0];
			key->daddr[1] = addr[1];
			key->ipv6 = true;
		}
		key->dport = udp->dest;
	} else {
		if (!ipv6) {
			key->daddr[0] = ip->saddr;
			key->daddr[1] = 0;
			key->ipv6 = false;
		} else {
			u64 *addr = (u64 *)&((struct ipv6hdr *)ip)->saddr;
			key->daddr[0] = addr[0];
			key->daddr[1] = addr[1];
			key->ipv6 = true;
		}
		key->dport = udp->source;
	}
	key->padding1 = 0;
	key->padding2 = 0;
}

static inline __attribute__((always_inline)) struct udp_info *
udp_port_info(struct udphdr *udp, u64 send)
{
	struct udp_info *info;
	int zero = 0;

	info = (struct udp_info *)map_lookup_elem(&tg_udp_info_heap, &zero);
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
__udp_send(struct __sk_buff *skb, u64 *cookie, struct iphdr *ip, bool ipv6,
	   s64 latency, struct udphdr *udp, int payload_sz,
	   struct udp_sensor_config *config,
	   struct latency_protocol_config *latency_config, u64 send, bool lazy,
	   struct socketmap_value *process)
{
	struct udp_info_value *value;
	int zero = 0;
	struct udp_info_key key;
	struct udp_info *info;

	key.cookie = *cookie;
	udp_key(&key, ip, ipv6, udp, send);

	value = (struct udp_info_value *)map_lookup_elem(&tg_udp_map, &key);

	if (!value) {
		value = (struct udp_info_value *)map_lookup_elem(&tg_udp_value_heap, &zero);
		if (!value)
			return 0;

		if (send)
			udp_info_tx_reset(value, payload_sz);
		else {
			udp_info_rx_reset(value, payload_sz);
			add_latency(latency_config, value->buckets, &value->latency_sum, latency);
		}

		/* Store the info in the entry for later use,
		 * and potentially for searching from userland
		 * in case we ever need to locate a socket */
		info = udp_info(ip, ipv6, udp, send);
		if (!info)
			return 0;
		if (!ipv6) {
			set_ipv6_addr_from_ipv4(value->saddr,
						info->saddr.ipv4);
			set_ipv6_addr_from_ipv4(value->daddr,
						info->daddr.ipv4);
			value->ipv6 = false;
		} else {
			copy_ipv6_addr(value->saddr, info->saddr.ipv6);
			copy_ipv6_addr(value->daddr, info->daddr.ipv6);
			value->ipv6 = true;
		}
		value->sport = info->sport;
		value->dport = info->dport;

		/* socket create time is when we see the first datagram, as a socket can
		 * support multiple pseudo-connections (using sendto()) and we shouldn't
		 * consider each to have been created when the actual socket was created.
		 * We should use the 'connect' time instead. */
		value->create_time = ktime_get_ns();

		/* If process was found, fill in the PID */
		if (process) {
			value->pid = process->key.pid;
			value->pid_ktime = process->key.ktime;
			emit_udp_connect_event(skb, cookie, value);
		}

		map_update_elem(&tg_udp_map, &key, value, 0);
	} else if (process && value->pid != process->key.pid) {
		/* PID doesn't match, so this must be a new socket */
		if (send)
			udp_info_tx_reset(value, payload_sz);
		else {
			udp_info_rx_reset(value, payload_sz);
			add_latency(latency_config, value->buckets, &value->latency_sum, latency);
		}
		info = udp_info(ip, ipv6, udp, send);
		if (!info)
			return 0;
		if (!ipv6) {
			set_ipv6_addr_from_ipv4(value->saddr,
						info->saddr.ipv4);
			set_ipv6_addr_from_ipv4(value->daddr,
						info->daddr.ipv4);
			value->ipv6 = false;
		} else {
			copy_ipv6_addr(value->saddr, info->saddr.ipv6);
			copy_ipv6_addr(value->daddr, info->daddr.ipv6);
			value->ipv6 = true;
		}
		value->sport = info->sport;
		value->dport = info->dport;
		value->pid = process->key.pid;
		value->pid_ktime = process->key.ktime;
		/* socket create time is when we see the first datagram, as a socket can
		 * support multiple pseudo-connections (using sendto()) and we shouldn't
		 * consider each to have been created when the actual socket was created.
		 * We should use the 'connect' time instead. */
		value->create_time = ktime_get_ns();

		emit_udp_connect_event(skb, cookie, value);
	} else {
		if (send)
			update_tx_value(value, payload_sz);
		else {
			update_rx_value(value, payload_sz);
			add_latency(latency_config, value->buckets, &value->latency_sum, latency);
		}
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
	 struct timestamp_option *ts_opt, struct udphdr *udp, u64 *cookie,
	 int payload_off, int payload_sz, u64 send, bool lazy, bool kp)
{
	struct udp_info_value *value;
	struct udp_sensor_config *config;
	struct socketmap_value *process;
	struct latency_config *latency_config = 0;
	struct latency_protocol_config *udp_latency = 0;
	int zero = 0;
	s64 latency = 0;

	config = (struct udp_sensor_config *)map_lookup_elem(&tg_udp_config_map, &zero);
	if (!config)
		return 1;

	if (!send) {
		latency_config = (struct latency_config *)map_lookup_elem(&tg_latency_config_map, &zero);
		if (!latency_config)
			return 1;

		if (ts_opt) {
			latency = calc_latency(latency_config->boot_ns,
					       bpf_ntohl(ts_opt->timestamp_low),
					       bpf_ntohl(ts_opt->timestamp_high));
			udp_latency = &latency_config->udp;
		}
	}

	process = lookup_socketmap(cookie);
	value = __udp_send(skb, cookie, ip, ipv6, latency, udp, payload_sz, config, udp_latency, send, lazy, process);
	if (!value)
		return 1;

	/* Only check sequence numbers on recevied packets. */
	if (!send && !kp && config->seq_check_app_id) {
		udp_seq_err_check(skb, skb_head, ip, ipv6, cookie, payload_off,
				  payload_sz, process, value, config);
	}

	if (config->dnsPorts[0] != 0) {
		if (dns_port_match(config->dnsPorts, value->sport,
				   bpf_ntohs(value->dport))) {
			if (!lazy && value->pid) {
				/* We subtract 1 from payload_sz because we need to +1 it
				 * later to sat verifier constraint that skb_load_bytes
				 * must be nonzero.
				 */
				emit_udp_payload_event(skb, ip, cookie, ipv6,
						       value, payload_off,
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
					store_udp_payload_event(
						skb, ip, cookie, ipv6, skb_head,
						value, payload_off,
						payload_sz - 1, kp);
			}
		}
	}
	return 1;
}

static inline __attribute__((always_inline)) void
udp_watermarks(void *ctx, u64 *cookie, struct udp_packet_details *packet, u64 send)
{
	struct udp_sensor_config *config;
	struct process_network_watermarks_config *c;
	struct socketmap_value *process;
	int zero = 0;

	config = (struct udp_sensor_config *)map_lookup_elem(&tg_udp_config_map, &zero);
	if (!config || !config->watermarks_enable)
		return;

	c = (struct process_network_watermarks_config *)map_lookup_elem(&tg_pn_watermarks_config_heap, &zero);
	if (!c)
		return;
	c->avg_window_size_ms = config->watermarks_avg_window_size_ms;
	c->window_size = config->watermarks_window_size;
	c->burst_trigger_mult = config->watermarks_burst_trigger_percent;
	c->dip_trigger_mult = config->watermarks_dip_trigger_percent;

	process = lookup_socketmap(cookie);
	/* If we don't have a process then we can't assign the watermarks information
	 * to it, and there is little else we can do.
	 * Additionally, if the sk address had previously been mapped to the
	 * process and kernel >=5.10, then it would have been remapped from
	 * the socket cookie by __udp_send() already.
	 */
	if (!process) {
		emit_ip_error_event(ctx, &packet->ip, cookie, packet->ipv6,
				    packet->ip.ip4.version, send + 1, 0, IP_ERROR_INET_WATERMARK_NO_PROCESS);
		return;
	}
	if (!process->key.pid) {
		emit_ip_error_event(ctx, &packet->ip, cookie, packet->ipv6,
				    packet->ip.ip4.version, send + 1, 0, IP_ERROR_INET_WATERMARK_NO_PID);
		return;
	}

	process_network_watermarks(ctx, process, IPPROTO_UDP, send, packet->payload_sz, c);
}

static inline __attribute__((always_inline)) void
inet_handler_lazy(struct __sk_buff *skb, u64 send)
{
	struct udp_packet_details *packet;
	u64 *cookie;
	int zero = 0;
	u8 proto;
	unsigned long int err = 0;
	struct timestamp_option *ts_opt = 0;
	u16 ethertype = bpf_ntohs((u16)skb->protocol);

	/* Only handle IPv4 and IPv6 here. */
	if (ethertype != ETH_P_IP && ethertype != ETH_P_IPV6)
		return;

	cookie = (u64 *)map_lookup_elem(&tg_udp_cookie_heap, &zero);
	if (!cookie)
		return;
	write_cookie(cookie, (u64)skb->sk);
	if (!*cookie) {
		emit_ip_error_event(skb, 0, cookie, false,
				    0, send + 1, 0, IP_ERROR_INET_NO_COOKIE);
		return;
	}

	packet = (struct udp_packet_details *)map_lookup_elem(&tg_udp_header_heap, &zero);
	if (!packet)
		return;

	if (skb_load_bytes(skb, 0, &packet->ip, sizeof(struct iphdr)) < 0) {
		emit_ip_error_event(skb, 0, cookie, false,
				    0, send + 1, 0, IP_ERROR_INET_READ_VER);
		return;
	}

	switch (packet->ip.ip4.version) {
	case 4:
		if (packet->ip.ip4.protocol != IPPROTO_UDP)
			return;
		packet->ipv6 = false;
		packet->udp_off = ip_payload_off(&packet->ip.ip4);
		if (packet->ip.ip4.ihl >=
		    ((sizeof(struct iphdr) + sizeof(struct timestamp_option)) /
		     sizeof(u32))) {
			/* Packet has at least enough space for the Timestamp IP Option,
			 * so check if the first option is the Timestamp option that we
			 * add to detect UDP latency.
			 */
			if (skb_load_bytes(
				    skb, sizeof(struct iphdr), &packet->ipopt,
				    sizeof(struct timestamp_option)) < 0) {
				emit_ip_error_event(
					skb, &packet->ip, cookie, false,
					packet->ip.ip4.version, send + 1, 0, IP_ERROR_INET_READ_IP_OPTION);
			} else {
				if (packet->ipopt.type == IPO_TYPE &&
				    packet->ipopt.magic ==
					    bpf_ntohl(IPO_MAGIC_W) &&
				    packet->ipopt.magic ==
					    packet->ipopt.magic2) {
					ts_opt = &packet->ipopt;
				}
			}
		}
		break;
	case 6:
		if (skb_load_bytes(skb, 0, &packet->ip,
				   sizeof(struct ipv6hdr)) < 0) {
			emit_ip_error_event(skb, 0, cookie, true,
					    packet->ip.ip4.version, send + 1, 0, IP_ERROR_INET_READ_IP);
			return;
		}
		packet->ipv6 = true;
		proto = get_ip6_proto(&packet->udp_off, &packet->ip.ip6, 0, skb,
				      0, true, false, &err);
		if (proto == IP_HEADER_ERROR) {
			emit_ip_error_event(skb, &packet->ip.ip6, cookie, true,
					    packet->ip.ip4.version, send + 1, 0, err);
			return;
		} else if (proto != IPPROTO_UDP) {
			return;
		}
		if (!packet->udp_off) {
			emit_ip_error_event(skb, &packet->ip, cookie, true,
					    packet->ip.ip4.version, send + 1, 0, IP_ERROR_INET_NO_PAYLOAD_OFFSET);
			return;
		}
		break;
	default:
		emit_ip_error_event(skb, 0, cookie, false,
				    packet->ip.ip4.version, send + 1, 0, IP_ERROR_INET_NO_VERSION);
		return;
	}
	if (skb_load_bytes(skb, packet->udp_off, &packet->udp,
			   sizeof(struct udphdr)) < 0) {
		emit_ip_error_event(skb, &packet->ip, cookie, packet->ipv6,
				    packet->ip.ip4.version, send + 1, 0, IP_ERROR_INET_READ_UDP);
		return;
	}
	packet->payload_sz = bpf_ntohs(packet->udp.len) - sizeof(struct udphdr);
	packet->payload_off = packet->udp_off + sizeof(struct udphdr);
	udp_send(skb, 0, &packet->ip.ip4, packet->ipv6, ts_opt, &packet->udp,
		 cookie, packet->payload_off, packet->payload_sz, send, true,
		 false);
	udp_watermarks(skb, cookie, packet, send);
}

static inline __attribute__((always_inline)) void
inet_handler_lazy_kp(void *ctx, struct sock *sk, struct sk_buff *skb, u64 send)
{
	struct udp_packet_details *packet;
	int zero = 0;
	u64 cookie;
	u8 proto;
	unsigned long int err = 0;
	struct timestamp_option *ts_opt = 0;
	u16 ethertype;

	if (probe_read(&ethertype, sizeof(ethertype), _(&(skb->protocol))) < 0)
		return;

	ethertype = bpf_ntohs(ethertype);

	/* Only handle IPv4 and IPv6 here. */
	if (ethertype != ETH_P_IP && ethertype != ETH_P_IPV6)
		return;

	write_cookie(&cookie, (u64)sk);
	if (!cookie) {
		emit_ip_error_event(ctx, 0, 0, false, 0, send + 1, 0, IP_ERROR_INET_NO_COOKIE);
		return;
	}
	packet = (struct udp_packet_details *)map_lookup_elem(&tg_udp_header_heap, &zero);
	if (!packet)
		return;

	packet->version = get_ip_version(&packet->network_header_off,
					 &packet->skb_head, skb);
	switch (packet->version) {
	case 4:
		if (!get_ip4_header(&packet->ip.ip4, packet->network_header_off,
				    packet->skb_head)) {
			emit_ip_error_event(ctx, 0, &cookie, false,
					    packet->version, send + 1, 0, IP_ERROR_INET_READ_IP);
			return;
		}
		packet->ipv6 = false;

		if (packet->ip.ip4.protocol != IPPROTO_UDP)
			return;
		if (packet->ip.ip4.ihl >=
		    ((sizeof(struct iphdr) + sizeof(struct timestamp_option)) /
		     sizeof(u32))) {
			/* Packet has at least enough space for the Timestamp IP Option,
			 * so check if the first option is the Timestamp option that we
			 * add to detect UDP latency.
			 */
			if (probe_read(&packet->ipopt,
				       sizeof(struct timestamp_option),
				       packet->skb_head +
					       packet->network_header_off +
					       sizeof(struct iphdr)) < 0) {
				emit_ip_error_event(
					ctx, &packet->ip, &cookie, false,
					packet->ip.ip4.version, send + 1, 0, IP_ERROR_INET_READ_IP_OPTION);
			} else {
				if (packet->ipopt.type == IPO_TYPE &&
				    packet->ipopt.magic ==
					    bpf_ntohl(IPO_MAGIC_W) &&
				    packet->ipopt.magic ==
					    packet->ipopt.magic2) {
					ts_opt = &packet->ipopt;
				}
			}
		}
		if (!get_udp_header(&packet->udp, &packet->payload_off,
				    packet->skb_head, skb)) {
			emit_ip_error_event(ctx, &packet->ip, &cookie, false,
					    packet->ip.ip4.version, send + 1, 0, IP_ERROR_INET_READ_UDP);
			return;
		}
		break;
	case 6:
		if (!get_ip6_header(&packet->ip.ip6, packet->network_header_off,
				    packet->skb_head)) {
			emit_ip_error_event(ctx, 0, &cookie, true,
					    packet->version, send + 1, 0, IP_ERROR_INET_READ_IP);
			return;
		}
		packet->ipv6 = true;
		proto = get_ip6_proto(0, &packet->ip.ip6,
				      packet->network_header_off,
				      packet->skb_head, 0, true, true, &err);
		if (proto == IP_HEADER_ERROR) {
			emit_ip_error_event(ctx, &packet->ip.ip6, &cookie, true,
					    packet->ip.ip6.version, send + 1, 0, err);
			return;
		} else if (proto != IPPROTO_UDP) {
			return;
		}
		if (!get_udp_header(&packet->udp, &packet->payload_off,
				    packet->skb_head, skb)) {
			emit_ip_error_event(ctx, &packet->ip, &cookie, true,
					    packet->ip.ip6.version, send + 1, 0, IP_ERROR_INET_READ_UDP);
			return;
		}
		break;
	default:
		emit_ip_error_event(ctx, 0, &cookie, false,
				    packet->version, send + 1, 0, IP_ERROR_INET_NO_VERSION);
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
	udp_send((struct __sk_buff *)ctx, packet->skb_head, &packet->ip.ip4, packet->ipv6, ts_opt,
		 &packet->udp, &cookie, packet->payload_off, packet->payload_sz,
		 send, true, true);
	udp_watermarks(ctx, &cookie, packet, send);
}

static inline __attribute__((always_inline)) void
inet_handler(struct __sk_buff *skb, u64 send)
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
	struct timestamp_option *ts_opt = 0;
	u16 ethertype = bpf_ntohs((u16)skb->protocol);

	/* Only handle IPv4 and IPv6 here. */
	if (ethertype != ETH_P_IP && ethertype != ETH_P_IPV6)
		return;

	write_cookie(&cookie, (u64)skb->sk);
	packet = (struct udp_packet_details *)map_lookup_elem(&tg_udp_header_heap, &zero);
	if (!packet)
		return;

	if (data + 1 > data_end) {
		emit_ip_error_event(skb, 0, &cookie, false,
				    0, send + 1, 0, IP_ERROR_INET_READ_VER);
		return;
	}

	ip = (struct iphdr *)data;

	switch (ip->version) {
	case 4:
		if (data + sizeof(struct iphdr) > data_end) {
			emit_ip_error_event(skb, 0, &cookie, false,
					    ip->version, send + 1, 0, IP_ERROR_INET_READ_IP);
			return;
		}
		if (ip->protocol != IPPROTO_UDP)
			return;
		if (ip->ihl >=
		    ((sizeof(struct iphdr) + sizeof(struct timestamp_option)) /
		     sizeof(u32))) {
			/* Packet has at least enough space for the Timestamp IP Option,
			 * so check if the first option is the Timestamp option that we
			 * add to detect UDP latency.
			 */
			if (data + sizeof(struct iphdr) +
				    sizeof(struct timestamp_option) >
			    data_end) {
				emit_ip_error_event(
					skb, ip, &cookie, false,
					ip->version, send + 1, 0, IP_ERROR_INET_READ_IP_OPTION);
			} else {
				ts_opt = (struct timestamp_option
						  *)(data +
						     sizeof(struct iphdr));
				if (ts_opt->type != IPO_TYPE ||
				    ts_opt->magic != bpf_ntohl(IPO_MAGIC_W) ||
				    ts_opt->magic != ts_opt->magic2) {
					ts_opt = 0;
				}
			}
		}
		packet->udp_off = ip_payload_off(ip);
		udp = (struct udphdr *)(data + packet->udp_off);
		if (data + packet->udp_off + sizeof(struct udphdr) > data_end) {
			emit_ip_error_event(skb, ip, &cookie, false,
					    ip->version, send + 1, 0, IP_ERROR_INET_READ_UDP);
			return;
		}
		packet->payload_sz =
			bpf_ntohs(udp->len) - sizeof(struct udphdr);
		packet->payload_off = packet->udp_off + sizeof(struct udphdr);
		udp_send(skb, 0, ip, false, ts_opt, udp, &cookie,
			 packet->payload_off, packet->payload_sz, send, false,
			 false);
		break;
	case 6:
		if (data + sizeof(struct ipv6hdr) > data_end) {
			emit_ip_error_event(skb, 0, &cookie, true,
					    ip->version, send + 1, 0, IP_ERROR_INET_READ_IP);
			return;
		}
		proto = get_ip6_proto(&packet->udp_off, (struct ipv6hdr *)ip, 0,
				      data, data_end, false, false, &err);
		if (proto == IP_HEADER_ERROR) {
			emit_ip_error_event(skb, (struct ipv6hdr *)ip, &cookie,
					    true, ip->version, send + 1, 0, err);
			return;
		} else if (proto != IPPROTO_UDP) {
			return;
		}
		if (!packet->udp_off) {
			emit_ip_error_event(skb, ip, &cookie, true,
					    ip->version, send + 1, 0, IP_ERROR_INET_NO_PAYLOAD_OFFSET);
			return;
		}
		udp = (struct udphdr *)(data + packet->udp_off);
		if (data + packet->udp_off + sizeof(struct udphdr) > data_end) {
			emit_ip_error_event(skb, ip, &cookie, true,
					    ip->version, send + 1, 0, IP_ERROR_INET_READ_UDP);
			return;
		}
		packet->payload_sz =
			bpf_ntohs(udp->len) - sizeof(struct udphdr);
		packet->payload_off = packet->udp_off + sizeof(struct udphdr);
		udp_send(skb, 0, ip, true, 0, udp, &cookie, packet->payload_off,
			 packet->payload_sz, send, false, false);
		break;
	default:
		emit_ip_error_event(skb, 0, &cookie, false,
				    ip->version, send + 1, 0, IP_ERROR_INET_NO_VERSION);
		return;
	}

	udp_watermarks(skb, &cookie, packet, send);
}

#endif //__BPF_INET_H_
