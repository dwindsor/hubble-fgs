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
#include "l3_config.h"
#include "bpf_process_network_watermarks.h"
#include "bpf_cookie.h"
#include "bpf_network_helpers.h"
#ifdef PROCESS_TREE
#include "process/process_tree.h"
#endif
#include "lib/address_family.h"
#include "bpf_tracing.h"
#include "dns/bpf_dns.h"
#include "bpf_udp_info.h"
#ifndef IS_KPROBE
#include "bpf_udp_mcast.h"
#endif
#include "fgs_rodata_config.h"

#ifdef IN_KERNEL_DNS
#include "parsers/dns/dns_parser.h"
#endif

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
	   struct udphdr *udp, int payload_off, int payload_sz, u64 egress,
	   struct socketmap_value *process)
{
	struct udp_info_value *value;
	bool dns_combined = false;
	struct udp_info_key *key;
	u64 cookie_ver = 0;
	int zero = 0;

	cookie_ver = process->version;

	key = (struct udp_info_key *)map_lookup_elem(&tg_p_l3_udp_key, &zero);
	if (!key)
		return 0;
	udp_key(key, &dns_combined, cookie, cookie_ver, ip, ipv6, udp, egress);
#ifndef IS_KPROBE
	// If this is a multicast packet, and we're observing multicast, and it
	// matches the ports we're observing, then extract the connection ID and
	// add it to the key to make the key unique between multiplexed multicast
	// traffic.
	key->tuple.conn_id = udp_mcast_get_conn_id(skb, ip, ipv6, cookie, payload_off, payload_sz, process, key);
#endif

	value = (struct udp_info_value *)map_lookup_elem(&tg_l3_udpsk, key);

	/* If the PID matches means this is a known connection key and its
	 * on a known process/socket binding then simply account for bytes
	 * and any other statistics needed.
	 */
	if (value && value->pid == process->key.pid) {
		if (egress) {
			update_tx_value(value, payload_sz);
#ifdef PROCESS_TREE
			send(skb, value->deny, &value->dst_key, payload_sz, false);
#endif
		} else {
			update_rx_value(value, payload_sz);
#ifdef PROCESS_TREE
			recv(skb, value->deny, &value->dst_key, payload_sz, false);
#endif
		}
#ifdef USE_BPF_TIMER
		update_udp_timer();
#endif
		return value;
	}

	if (!value) {
		value = (struct udp_info_value *)map_lookup_elem(&tg_h_udp_value, &zero);
		if (!value)
			return 0;
	}

	/* Otherwise this is a new UDP key over an existing socket or the
	 * socket has moved to a new pid. Either way restart statistics and
	 * create a new mapping.
	 */
	if (egress)
		udp_info_tx_reset(value, payload_sz);
	else
		udp_info_rx_reset(value, payload_sz);

	/* socket create time is when we see the first datagram, as a socket can
	 * support multiple pseudo-connections (using sendto()) and we shouldn't
	 * consider each to have been created when the actual socket was created.
	 * We should use the 'connect' time instead. */
	value->create_time = tg_get_ktime();

	/* Update process binding and generate connect event */
	value->pid = process->key.pid;
	value->pid_ktime = process->key.ktime;
	process->protocol = IPPROTO_UDP;
	emit_udp_connect_event(skb, cookie, cookie_ver, value->ps_version, key, value);
#ifndef IS_KPROBE
	if (FGS_CONFIG(CGROUP_PROBE_READ))
		add_socket_tuple_map(&key->tuple, cookie);
	else
		add_socket_tuple_map_from_skb(cookie, skb, IPPROTO_UDP);
#endif
#ifdef PROCESS_TREE
	struct udpsocketmap_value *udpsock;

	udpsock = map_lookup_elem(&tg_h_udp_sockval, &zero);
	if (!udpsock)
		return 0;
	udpsock->key = process->key;
	value->deny = process_socketmap_add_udp(udpsock, &key->tuple, egress != 0);
	value->dst_key = udpsock->dst_key;
	count_session(&value->dst_key);
#endif
	add_udp_map(key, value);
#ifdef PROCESS_TREE
	if (egress)
		send(skb, value->deny, &value->dst_key, payload_sz, false);
	else
		recv(skb, value->deny, &value->dst_key, payload_sz, false);
#endif
	return value;
}

/* Lazy versions of udp send do not support copying the payload to
 * user land, as this isn't provided by older kernels.
 * We take a boolean, dns, to specify if we are sending DNS payloads
 * to userland. The reason we need this rather than a simple lookup
 * on config->dns_ports[0] is to force clang to exclude the DNS code
 * because it contains a call to skb_load_bytes() which we can't have
 * on the kprobe solution for older kernels.
 */
static inline __attribute__((always_inline)) int
udp_send(struct __sk_buff *skb, void *skb_head, struct iphdr *ip, bool ipv6,
	 struct udphdr *udp, u64 *cookie,
	 int payload_off, int payload_sz, u64 send, bool dns_send_userspace)
{
	struct socketmap_value *process = 0;
	struct udp_info_value *value;
	struct udp_info_key *key;
	u64 cookie_ver = 0;
	int zero = 0;

	if (*cookie) {
		__u64 c = *cookie;
		process = lookup_socketmap(&c);
	}
	if (!process) {
		// Not having a process means this is a kernel socket datagram.
		return 1;
	}

	value = __udp_send(skb, cookie, ip, ipv6, udp, payload_off, payload_sz, send, process);
	if (!value)
		return 1;

	key = (struct udp_info_key *)map_lookup_elem(&tg_p_l3_udp_key, &zero);
	if (!key)
		return 1;

#ifndef IS_KPROBE
	if (FGS_CONFIG(TG_MULTICAST_INSPECTION))
		udp_check_multicast(skb, ip, ipv6, cookie, payload_off,
				    payload_sz, send, process, key, value);
#endif

	cookie_ver = process->version;

	if (dns_send_userspace)
		udp_dns(skb, skb_head, key, value, ip, ipv6, send, cookie, cookie_ver, payload_off, payload_sz);
	return 1;
}

static inline __attribute__((always_inline)) void
udp_watermarks(void *ctx, u64 *cookie, struct iphdr *ip, int payload_sz, bool ipv6, u64 send)
{
	struct process_network_watermarks_config *c;
	struct udp_sensor_config *config;
	struct socketmap_value *process;
	struct cfg_value *l3cfg;
	int zero = 0;
	u64 __cookie;

	l3cfg = getl3cfg();
	if (!l3cfg)
		return;
	config = &l3cfg->udp;
	if (!config->watermarks_enable)
		return;

	c = (struct process_network_watermarks_config *)map_lookup_elem(&tg_h_l3_wtmk_c, &zero);
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
	packet = (struct udp_packet_details *)map_lookup_elem(&tg_h_udp_header, &zero);
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
				      packet->skb_head, 0, 0, true, &err);
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
	udp_send((struct __sk_buff *)ctx, packet->skb_head, &packet->ip.ip4, packet->ipv6,
		 &packet->udp, &cookie, packet->payload_off, packet->payload_sz, send, true);
	udp_watermarks(ctx, &cookie, &packet->ip.ip4, packet->payload_sz, packet->ipv6, send);
	return;

inet_handler_lazy_kp_emit_error:
	emit_ip_error_event(ctx, ip, &cookie, ipv6, packetver, send + 1, 0, err);
}

int udp_handler_ip4(struct __sk_buff *skb, int send)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (long *)(long)skb->data;
	bool dns_send_userspace = true;
	int payload_sz, payload_off;
	struct udphdr *udp, udptmp;
	struct handler_vars *vars;
	uint32_t zero = 0;
	struct iphdr *ip;
	u8 udp_off;
	int err;
#ifdef IN_KERNEL_DNS
	struct cfg_value *l3cfg;
#endif

	if (!skb)
		return SK_PASS;

	vars = (struct handler_vars *)map_lookup_elem(&tg_p_l3_dsptchr, &zero);
	if (!vars)
		return SK_PASS;

	if (data + sizeof(struct iphdr) > data_end)
		ip = &vars->ip;
	else
		ip = (struct iphdr *)data;

	udp_off = ip_payload_off(ip);
	asm volatile("%[udp_off] &= 0xff;\n"
		     : [udp_off] "+r"(udp_off)
		     :);
	if (data + udp_off + sizeof(struct udphdr) <= data_end) {
		udp = (struct udphdr *)(data + udp_off);
	} else {
		err = skb_load_bytes(skb, udp_off, &udptmp, sizeof(struct udphdr));
		if (err < 0) {
			emit_ip_error_event(skb, ip, &vars->cookie, false,
					    false, send + 1, 0, IP_ERROR_INET_READ_UDP);
			return SK_PASS;
		}
		udp = &udptmp;
	}
	payload_sz = bpf_ntohs(udp->len) - sizeof(struct udphdr);
	payload_off = udp_off + sizeof(struct udphdr);
#ifdef IN_KERNEL_DNS
	l3cfg = getl3cfg();
	if (FGS_CONFIG(DNS_PARSER_ENABLED) && l3cfg && dns_port_match(l3cfg->udp.dns_ports, bpf_htons(udp->source), bpf_htons(udp->dest)))
		dns_send_userspace = !!parse_dns(skb, payload_off, send);
#endif
	udp_send(skb, 0, ip, false, udp, &vars->cookie,
		 payload_off, payload_sz, send, dns_send_userspace);
	udp_watermarks(skb, &vars->cookie, ip, payload_sz, false, send);
	/* TODO: UDP enforcement is observability-only. udp_send() computes the
	 * deny verdict and records it in stats, but the handler always returns
	 * SK_PASS so no UDP traffic is actually dropped.
	 */
	return SK_PASS;
}

int udp_handler_ip6(struct __sk_buff *skb, u16 udp_off, int send)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (long *)(long)skb->data;
	bool dns_send_userspace = true;
	int payload_sz, payload_off;
	struct handler_vars *vars;
	struct udphdr *udp, cpy;
	struct ipv6hdr *ip6;
	uint32_t zero = 0;
#ifdef IN_KERNEL_DNS
	struct cfg_value *l3cfg;
#endif

	if (!skb)
		return SK_PASS;

	vars = (struct handler_vars *)map_lookup_elem(&tg_p_l3_dsptchr, &zero);
	if (!vars)
		return SK_PASS;
	ip6 = &vars->ip6;

	if (!udp_off) {
		emit_ip_error_event(skb, (struct iphdr *)ip6, &vars->cookie, true,
				    6, send + 1, 0, IP_ERROR_INET_NO_PAYLOAD_OFFSET);
		return SK_PASS;
	}
	asm volatile("%[udp_off] &= 0xfff;\n"
		     : [udp_off] "+r"(udp_off)
		     :);
	udp = (struct udphdr *)(data + udp_off);
	if (udp + sizeof(struct udphdr) > data_end) {
		if (skb_load_bytes(skb, udp_off, &cpy, sizeof(struct udphdr)) < 0) {
			emit_ip_error_event(skb, (struct iphdr *)ip6, &vars->cookie, 6,
					    6, send + 1, 0, IP_ERROR_INET_READ_UDP);
			return SK_PASS;
		}
		udp = &cpy;
	}
	payload_sz = bpf_ntohs(udp->len) - sizeof(struct udphdr);
	payload_off = udp_off + sizeof(struct udphdr);
#ifdef IN_KERNEL_DNS
	l3cfg = getl3cfg();
	if (FGS_CONFIG(DNS_PARSER_ENABLED) && l3cfg && dns_port_match(l3cfg->udp.dns_ports, bpf_htons(udp->source), bpf_htons(udp->dest)))
		dns_send_userspace = !!parse_dns(skb, payload_off, send);
#endif
	udp_send(skb, 0, (struct iphdr *)ip6, true, udp, &vars->cookie,
		 payload_off, payload_sz, send, dns_send_userspace);
	udp_watermarks(skb, &vars->cookie, (struct iphdr *)ip6, payload_sz, true, send);
	/* TODO: UDP enforcement is observability-only. udp_send() computes the
	 * deny verdict and records it in stats, but the handler always returns
	 * SK_PASS so no UDP traffic is actually dropped.
	 */
	return SK_PASS;
}
#endif //__BPF_INET_H_
