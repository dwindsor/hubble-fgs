// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef __BPF_UDP_INET_H_
#define __BPF_UDP_INET_H_

#include "vmlinux.h"
#include "api.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "bpf_udp_event.h"
#include "bpf_udp_config.h"
#include "bpf_latency.h"
#include "bpf_process_network_watermarks.h"
#include "bpf_cookie.h"
#include "bpf_network_helpers.h"
#include "bpf_udp_seq_error.h"
#include "lib/address_family.h"
#include "bpf_tracing.h"
#include "dns/bpf_dns.h"
#include "bpf_udp_info.h"

#include "../../../parsers/dns/dns_parser.h"

static inline __attribute__((always_inline)) u8 ip_payload_off(struct iphdr *ip)
{
	u8 ip_off;

	ip_off = ip->ihl;
	ip_off &= 0x0f;
	ip_off *= 4;
	return ip_off;
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
	   struct latency_protocol_config *latency_config, u64 send,
	   struct socketmap_value *process,
	   struct udp_info_key *key)
{
	struct udp_info_value *value;
	u64 cookie_ver = 0;

	if (process)
		cookie_ver = process->version;

	udp_key(key, cookie, cookie_ver, ip, ipv6, udp, send);

	value = (struct udp_info_value *)map_lookup_elem(&tg_udp_map, key);

	/* If the PID matches means this is a known connection key and its
	 * on a known process/socket binding then simply account for bytes
	 * and any other statistics needed.
	 */
	if (process && value && value->pid == process->key.pid) {
		if (send)
			update_tx_value(value, payload_sz);
		else {
			update_rx_value(value, payload_sz);
			add_latency(latency_config, value->buckets, &value->latency_sum, latency);
		}
		return value;
	}

	if (!value) {
		int zero = 0;

		value = (struct udp_info_value *)map_lookup_elem(&tg_udp_value_heap, &zero);
		if (!value)
			return 0;

		value->pid = 0;
		value->pid_ktime = 0;
	}

	/* Otherwise this is a new UDP key over an existing socket or the
	 * socket has moved to a new pid. Either way restart statistics and
	 * create a new mapping.
	 */
	if (send)
		udp_info_tx_reset(value, payload_sz);
	else {
		udp_info_rx_reset(value, payload_sz);
		add_latency(latency_config, value->buckets, &value->latency_sum, latency);
	}

	/* socket create time is when we see the first datagram, as a socket can
	 * support multiple pseudo-connections (using sendto()) and we shouldn't
	 * consider each to have been created when the actual socket was created.
	 * We should use the 'connect' time instead. */
	value->create_time = ktime_get_ns();

	/* Update process binding and generate connect event */
	if (process) {
		value->pid = process->key.pid;
		value->pid_ktime = process->key.ktime;
		process->protocol = IPPROTO_UDP;
		emit_udp_connect_event(skb, cookie, cookie_ver, value->ps_version, key, value);
#ifndef IS_KPROBE
#ifdef TRACK_ICMP_FROM_SKB
		add_socket_tuple_map_from_skb(cookie, skb, IPPROTO_UDP);
#else
		add_socket_tuple_map(&key->tuple, cookie);
#endif
#endif
	}

	add_udp_map(key, value);
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
	 int payload_off, int payload_sz, u64 send)
{
	struct latency_protocol_config *udp_latency = 0;
	struct latency_config *latency_config = 0;
	struct socketmap_value *process;
	struct udp_info_value *value;
	struct udp_info_key key = { 0 };
	u64 cookie_ver = 0;
	s64 latency = 0;
	int zero = 0;

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

	if (*cookie) {
		__u64 c = *cookie;
		process = lookup_socketmap(&c);
	} else {
		process = 0;
	}

	value = __udp_send(skb, cookie, ip, ipv6, latency, udp, payload_sz, udp_latency, send, process, &key);
	if (!value)
		return 1;

	/* Only check sequence numbers on recevied packets. */
	if (!send)
		udp_seq_err_check(skb, skb_head, ip, ipv6, cookie, payload_off,
				  payload_sz, process, &key, value);

	if (process)
		cookie_ver = process->version;
	udp_dns(skb, skb_head, &key, value, ip, ipv6, cookie, cookie_ver, payload_off, payload_sz);
	return 1;
}

static inline __attribute__((always_inline)) void
udp_watermarks(void *ctx, u64 *cookie, struct iphdr *ip, int payload_sz, bool ipv6, u64 send)
{
	struct process_network_watermarks_config *c;
	struct udp_sensor_config *config;
	struct socketmap_value *process;
	int zero = 0;
	u64 __cookie;

	config = get_udp_config();
	if (!config || !config->watermarks_enable)
		return;

	c = (struct process_network_watermarks_config *)map_lookup_elem(&tg_pn_watermarks_config_heap, &zero);
	if (!c)
		return;
	c->avg_window_size_ms = config->watermarks_avg_window_size_ms;
	c->window_size = config->watermarks_window_size;
	c->burst_trigger_mult = config->watermarks_burst_trigger_percent;
	c->dip_trigger_mult = config->watermarks_dip_trigger_percent;

	__cookie = *cookie;
	process = lookup_socketmap(&__cookie);
	/* If we don't have a process then we can't assign the watermarks information
	 * to it, and there is little else we can do.
	 * Additionally, if the sk address had previously been mapped to the
	 * process and kernel >=5.10, then it would have been remapped from
	 * the socket cookie by __udp_send() already.
	 */
	if (!process) {
		emit_ip_error_event(ctx, ip, cookie, ipv6,
				    ip->version, send + 1, 0, IP_ERROR_INET_WATERMARK_NO_PROCESS);
		return;
	}
	if (!process->key.pid) {
		emit_ip_error_event(ctx, ip, cookie, ipv6,
				    ip->version, send + 1, 0, IP_ERROR_INET_WATERMARK_NO_PID);
		return;
	}

	process_network_watermarks(ctx, process, IPPROTO_UDP, send, payload_sz, c);
}

static inline __attribute__((always_inline)) void
inet_handler_lazy_kp(void *ctx, struct sock *sk, struct sk_buff *skb, u64 send)
{
	struct timestamp_option *ts_opt = 0;
	struct udp_packet_details *packet;
	unsigned long int err = 0;
	u8 proto, packetver = 0;
	bool ipv6 = false;
	u16 ethertype;
	int zero = 0;
	void *ip = 0;
	u64 cookie;

	if (probe_read_kernel(&ethertype, sizeof(ethertype), _(&(skb->protocol))) < 0)
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
			err = IP_ERROR_INET_READ_IP;
			packetver = packet->version;
			goto inet_handler_lazy_kp_emit_error;
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
			if (probe_read_kernel(&packet->ipopt,
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
			err = IP_ERROR_INET_READ_UDP;
			packetver = packet->ip.ip4.version;
			ip = &packet->ip;
			goto inet_handler_lazy_kp_emit_error;
		}
		break;
	case 6:
		ipv6 = true;
		if (!get_ip6_header(&packet->ip.ip6, packet->network_header_off,
				    packet->skb_head)) {
			err = IP_ERROR_INET_READ_IP;
			packetver = packet->version;
			goto inet_handler_lazy_kp_emit_error;
		}
		packet->ipv6 = true;
		proto = get_ip6_proto(0, &packet->ip.ip6,
				      packet->network_header_off,
				      packet->skb_head, 0, true, true, &err);
		if (proto == IP_HEADER_ERROR) {
			packetver = packet->ip.ip6.version;
			ip = &packet->ip.ip6;
			goto inet_handler_lazy_kp_emit_error;
		} else if (proto != IPPROTO_UDP) {
			return;
		}
		if (!get_udp_header(&packet->udp, &packet->payload_off,
				    packet->skb_head, skb)) {
			err = IP_ERROR_INET_READ_UDP;
			packetver = packet->ip.ip6.version;
			ip = &packet->ip;
			goto inet_handler_lazy_kp_emit_error;
		}
		break;
	default:
		err = IP_ERROR_INET_NO_VERSION;
		packetver = packet->version;
		goto inet_handler_lazy_kp_emit_error;
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
		 &packet->udp, &cookie, packet->payload_off, packet->payload_sz, send);
	udp_watermarks(ctx, &cookie, &packet->ip.ip4, packet->payload_sz, packet->ipv6, send);
	return;

inet_handler_lazy_kp_emit_error:
	emit_ip_error_event(ctx, ip, &cookie, ipv6, packetver, send + 1, 0, err);
}

#ifdef SKB_LOAD_BYTES
static inline __attribute__((always_inline)) int
udp_handler_ip4(struct __sk_buff *skb, struct iphdr *ip, u64 *cookie, int send)
{
	size_t ipopts = sizeof(struct iphdr) + sizeof(struct timestamp_option);
	size_t ipopts_b = ipopts / sizeof(u32);
	struct timestamp_option *ts_opt = 0;
	struct timestamp_option ipopt;
	int payload_off, payload_sz;
	struct udphdr udp;
	u8 udp_off;

	if (!skb)
		return SK_PASS;
	if (!ip)
		return SK_PASS;
	if (!cookie)
		return SK_PASS;

	if (ip->ihl >= ipopts_b) {
		int err;

		/* Packet has at least enough space for the Timestamp IP Option,
		 * so check if the first option is the Timestamp option that we
		 * add to detect UDP latency.
		 */
		err = skb_load_bytes(skb, sizeof(struct iphdr), &ipopt, sizeof(struct timestamp_option));
		if (err < 0) {
			emit_ip_error_event(
				skb, &ip, cookie, false,
				false, send + 1, 0, IP_ERROR_INET_READ_IP_OPTION);
		} else {
			if (ipopt.type == IPO_TYPE &&
			    ipopt.magic == bpf_ntohl(IPO_MAGIC_W) &&
			    ipopt.magic == ipopt.magic2) {
				ts_opt = &ipopt;
			}
		}
	}

	udp_off = ip_payload_off(ip);
	if (skb_load_bytes(skb, udp_off, &udp, sizeof(struct udphdr)) < 0) {
		emit_ip_error_event(skb, ip, cookie, false,
				    false, send + 1, 0, IP_ERROR_INET_READ_UDP);
		return SK_PASS;
	}

	payload_sz = bpf_ntohs(udp.len) - sizeof(struct udphdr);
	payload_off = udp_off + sizeof(struct udphdr);
	udp_send(skb, 0, ip, false, ts_opt, &udp, cookie, payload_off, payload_sz, send);
	udp_watermarks(skb, cookie, ip, payload_sz, false, send);
	return SK_PASS;
}
#else
int udp_handler_ip4(struct __sk_buff *skb, struct iphdr *ip, u64 *cookie, int send)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (long *)(long)skb->data;
	struct timestamp_option *ts_opt = 0;

	size_t ipopts = sizeof(struct iphdr) + sizeof(struct timestamp_option);
	size_t ipopts_b = ipopts / sizeof(u32);

	int payload_sz, payload_off;
	struct udphdr *udp;
	u8 udp_off;

	if (!skb)
		return SK_PASS;
	if (!ip)
		return SK_PASS;
	if (!cookie)
		return SK_PASS;

	if (ip->ihl >= ipopts_b) {
		/* Packet has at least enough space for the Timestamp IP Option,
		 * so check if the first option is the Timestamp option that we
		 * add to detect UDP latency.
		 */
		if (data + ipopts > data_end) {
			emit_ip_error_event(
				skb, ip, cookie, false,
				ip->version, send + 1, 0, IP_ERROR_INET_READ_IP_OPTION);
		} else {
			ts_opt = (struct timestamp_option *)(data + sizeof(struct iphdr));
			if (ts_opt->type != IPO_TYPE ||
			    ts_opt->magic != bpf_ntohl(IPO_MAGIC_W) ||
			    ts_opt->magic != ts_opt->magic2) {
				ts_opt = 0;
			}
		}
	}
	udp_off = ip_payload_off(ip);
	asm volatile("%[udp_off] &= 0xff;\n"
		     : [udp_off] "+r"(udp_off)
		     :);
	udp = (struct udphdr *)(data + udp_off);
	if (data + udp_off + sizeof(struct udphdr) > data_end) {
		emit_ip_error_event(skb, ip, cookie, false,
				    ip->version, send + 1, 0, IP_ERROR_INET_READ_UDP);
		return SK_PASS;
	}
	payload_sz = bpf_ntohs(udp->len) - sizeof(struct udphdr);
	payload_off = udp_off + sizeof(struct udphdr);
	// TODO(mtardy) make parse_dns a real function call: the main issue is that
	// the stack is already quite busy here.
	parse_dns(skb);
	udp_send(skb, 0, ip, false, ts_opt, udp, cookie,
		 payload_off,
		 payload_sz, send);
	udp_watermarks(skb, cookie, ip, payload_sz, false, send);
	return SK_PASS;
}
#endif // SKB_LOAD_BYTES

#ifdef SKB_LOAD_BYTES
static inline __attribute__((always_inline)) int
udp_handler_ip6(struct __sk_buff *skb, struct ipv6hdr *ip6, u64 *cookie, u16 off, int send)
{
	int payload_off, payload_sz;
	unsigned long err;
	struct udphdr udp;
	int ver_ip6 = 6;
	u16 udp_off;

	if (!skb)
		return SK_PASS;
	if (!ip6)
		return SK_PASS;
	if (!cookie)
		return SK_PASS;

	get_ip6_proto(&udp_off, ip6, 0, skb, 0, true, false, &err);
	if (!udp_off) {
		emit_ip_error_event(skb, ip6, cookie, true,
				    ver_ip6, send + 1, 0, IP_ERROR_INET_NO_PAYLOAD_OFFSET);
		return SK_PASS;
	}

	if (skb_load_bytes(skb, udp_off, &udp, sizeof(struct udphdr)) < 0) {
		emit_ip_error_event(skb, (struct iphdr *)ip6, cookie, ver_ip6,
				    6, send + 1, 0, IP_ERROR_INET_READ_UDP);
		return SK_PASS;
	}
	payload_sz = bpf_ntohs(udp.len) - sizeof(struct udphdr);
	payload_off = udp_off + sizeof(struct udphdr);
	udp_send(skb, 0, (struct iphdr *)ip6, true, 0, &udp,
		 cookie, payload_off, payload_sz, send);
	udp_watermarks(skb, cookie, (struct iphdr *)ip6, payload_sz, true, send);

	return SK_PASS;
}
#else
int udp_handler_ip6(struct __sk_buff *skb, struct ipv6hdr *ip6, u64 *cookie, u16 off, int send)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (long *)(long)skb->data;
	int payload_sz, payload_off;
	struct udphdr *udp, cpy;
	unsigned long err;
	u16 udp_off;

	if (!skb)
		return SK_PASS;
	if (!ip6)
		return SK_PASS;
	if (!cookie)
		return SK_PASS;

	get_ip6_proto(&udp_off, ip6, 0, skb, 0, true, false, &err);
	if (!udp_off) {
		emit_ip_error_event(skb, (struct iphdr *)ip6, cookie, true,
				    6, send + 1, 0, IP_ERROR_INET_NO_PAYLOAD_OFFSET);
		return SK_PASS;
	}
	asm volatile("%[udp_off] &= 0xfff;\n"
		     : [udp_off] "+r"(udp_off)
		     :);
	udp = (struct udphdr *)(data + udp_off);
	if (udp + sizeof(struct udphdr) > data_end) {
		if (skb_load_bytes(skb, udp_off, &cpy, sizeof(struct udphdr)) < 0) {
			emit_ip_error_event(skb, (struct iphdr *)ip6, cookie, 6,
					    6, send + 1, 0, IP_ERROR_INET_READ_UDP);
			return SK_PASS;
		}
		udp = &cpy;
	}
	payload_sz = bpf_ntohs(udp->len) - sizeof(struct udphdr);
	payload_off = udp_off + sizeof(struct udphdr);
	udp_send(skb, 0, (struct iphdr *)ip6, true, 0, udp, cookie,
		 payload_off,
		 payload_sz, send);
	udp_watermarks(skb, cookie, (struct iphdr *)ip6, payload_sz, true, send);
	return SK_PASS;
}
#endif // SKB_LOAD_BYTES
#endif //__BPF_INET_H_
