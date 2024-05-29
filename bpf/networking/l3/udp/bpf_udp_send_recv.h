// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef __BPF_UDP_SEND_RECV_H_
#define __BPF_UDP_SEND_RECV_H_

#include "vmlinux.h"

#include "api.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "bpf_udp_event.h"
#include "bpf_cookie.h"
#include "bpf_network_helpers.h"
#include "bpf_tracing.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

#define MSG_PEEK 2

struct udp_sock_info {
	struct sock *sk;
	struct msghdr *msg;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u64);
	__type(value, struct udp_sock_info);
	__uint(max_entries, 16384);
} tg_udp_retprobe_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, int64_t);
	__uint(max_entries, 1);
} tg_udp_retprobe_map_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct udp_sock_info);
	__uint(max_entries, 1);
} udp_sock_info_heap SEC(".maps");

static inline __attribute__((always_inline)) struct udp_info *
udp4_get_info(struct udp_sock_info *sock_info)
{
	struct msghdr *msg = sock_info->msg;
	struct sock *sk = sock_info->sk;
	struct sockaddr_in *in;
	struct inet_sock *inet;
	struct udp_info *info;
	int zero = 0;
	int namelen;

	inet = (struct inet_sock *)sk;

	info = (struct udp_info *)map_lookup_elem(&tg_udp_info_heap, &zero);
	if (!info)
		return 0;

	probe_read_kernel(&in, sizeof(void *), _(&(msg->msg_name)));
	probe_read_kernel(&namelen, sizeof(int), _(&(msg->msg_namelen)));
	info->ipv6 = false;
	if (in && namelen >= sizeof(*in)) {
		probe_read_kernel(&info->daddr.ipv4, sizeof(u32),
				  _(&(in->sin_addr.s_addr)));
		probe_read_kernel(&info->dport, sizeof(u16), _(&(in->sin_port)));
	} else {
		probe_read_kernel(&info->daddr.ipv4, sizeof(u32),
				  _(&(sk->__sk_common.skc_daddr)));
		probe_read_kernel(&info->dport, sizeof(u16),
				  _(&(sk->__sk_common.skc_dport)));
	}
	probe_read_kernel(&info->saddr.ipv4, sizeof(u32), _(&(inet->inet_saddr)));
	probe_read_kernel(&info->sport, sizeof(u16), _(&(inet->inet_sport)));
	info->padding[0] = 0;
	info->padding[1] = 0;
	info->padding[2] = 0;
	/* Addresses are expected to be in network byte order with ports
	 * in host byte order.
	 */
	info->sport = bpf_ntohs(info->sport);
	info->dport = bpf_ntohs(info->dport);

	return info;
}

static inline __attribute__((always_inline)) struct udp_info *
udp6_get_info(struct udp_sock_info *sock_info)
{
	struct msghdr *msg = sock_info->msg;
	struct sock *sk = sock_info->sk;
	struct ipv6_pinfo *pinet6;
	struct sockaddr_in6 *in;
	struct inet_sock *inet;
	struct udp_info *info;
	int zero = 0;
	int namelen;

	inet = (struct inet_sock *)sk;

	info = (struct udp_info *)map_lookup_elem(&tg_udp_info_heap, &zero);
	if (!info)
		return 0;

	probe_read_kernel(&in, sizeof(void *), _(&(msg->msg_name)));
	probe_read_kernel(&namelen, sizeof(int), _(&(msg->msg_namelen)));
	if (in && namelen >= sizeof(*in)) {
		probe_read_kernel(&info->daddr, sizeof(struct in6_addr),
				  _(&(in->sin6_addr)));
		probe_read_kernel(&info->dport, sizeof(u16), _(&(in->sin6_port)));
	} else {
		probe_read_kernel(&info->daddr, sizeof(struct in6_addr),
				  _(&(sk->__sk_common.skc_v6_daddr)));
		probe_read_kernel(&info->dport, sizeof(u16),
				  _(&(sk->__sk_common.skc_dport)));
	}
	probe_read_kernel(&pinet6, sizeof(struct ipv6_pinfo *), _(&(inet->pinet6)));
	probe_read_kernel(&info->saddr, sizeof(struct in6_addr), _(&(pinet6->saddr)));
	probe_read_kernel(&info->sport, sizeof(u16), _(&(inet->inet_sport)));
	info->ipv6 = true;
	info->padding[0] = 0;
	info->padding[1] = 0;
	info->padding[2] = 0;
	/* Addresses are expected to be in network byte order with ports
	 * in host byte order.
	 */
	info->sport = bpf_ntohs(info->sport);
	info->dport = bpf_ntohs(info->dport);

	return info;
}

static inline __attribute__((always_inline)) void
udp_key_daddr_dport(struct udp_info_key *key, u64 *cookie, u32 cookie_ver, struct udp_sock_info *sock_info)
{
	struct msghdr *msg = sock_info->msg;
	struct sock *sk = sock_info->sk;
	struct sockaddr_in6 *in6;
	struct sockaddr_in *in;
	int namelen;

	probe_read_kernel(&in, sizeof(void *), _(&(msg->msg_name)));
	in6 = (struct sockaddr_in6 *)in;
	probe_read_kernel(&namelen, sizeof(int), _(&(msg->msg_namelen)));

	if (!key->ipv6) {
		u32 daddr;
		if (in && namelen >= sizeof(*in)) {
			probe_read_kernel(&daddr, sizeof(daddr), _(&(in->sin_addr.s_addr)));
			key->daddr[0] = daddr;
			key->daddr[1] = 0;
			probe_read_kernel(&key->dport, sizeof(key->dport), _(&(in->sin_port)));
		} else {
			probe_read_kernel(&daddr, sizeof(daddr), _(&(sk->__sk_common.skc_daddr)));
			key->daddr[0] = daddr;
			key->daddr[1] = 0;
			probe_read_kernel(&key->dport, sizeof(key->dport), _(&(sk->__sk_common.skc_dport)));
		}
	} else {
		if (in6 && namelen >= sizeof(*in6)) {
			probe_read_kernel(&key->daddr, sizeof(struct in6_addr), _(&(in6->sin6_addr)));
			probe_read_kernel(&key->dport, sizeof(key->dport), _(&(in6->sin6_port)));
		} else {
			probe_read_kernel(&key->daddr, sizeof(struct in6_addr), _(&(sk->__sk_common.skc_v6_daddr)));
			probe_read_kernel(&key->dport, sizeof(key->dport), _(&(sk->__sk_common.skc_dport)));
		}
	}
	key->dport = bpf_ntohs(key->dport);
	key->cookie = *cookie;
	key->padding = 0;
	key->version = cookie_ver;
}

static inline __attribute__((always_inline)) int
add_process_ctx(struct udp_info_value *value)
{
	struct execve_map_value *process;
	bool walker;
	u32 ppid;

	process = event_find_curr(&ppid, &walker);
	if (process) {
		value->pid = process->key.pid;
		value->pid_ktime = process->key.ktime;
		return 1;
	}
	return 0;
}

static inline __attribute__((always_inline)) void
add_to_retprobe_map(void *ctx, u64 cookie, u64 *key, struct udp_sock_info *value)
{
	int zero = 0;
	long ret;

	ret = map_update_elem(&tg_udp_retprobe_map, key, value, 0);
	if (ret < 0) {
		emit_ip_error_event(ctx, 0, 0, false,
				    0, 2, 0, IP_ERROR_UDP_RETPROBE_ADD);
	} else {
		u32 *stat = (u32 *)map_lookup_elem(&tg_udp_retprobe_map_stats, &zero);
		if (stat) {
			*stat = *stat + 1;
		}
	}
}

static inline __attribute__((always_inline)) struct udp_sock_info *
lookup_retprobe_map(void *ctx, u64 *key)
{
	return (struct udp_sock_info *)map_lookup_elem(&tg_udp_retprobe_map, key);
}

#define ENOENT 2

static inline __attribute__((always_inline)) void
udp_retprobe_map_dec(void)
{
	int zero = 0;
	u32 *stat;

	stat = (u32 *)map_lookup_elem(&tg_udp_retprobe_map_stats, &zero);
	if (!stat)
		return;

	*stat = *stat - 1;
}

static inline __attribute__((always_inline)) void
del_from_retprobe_map(void *ctx, u64 cookie, struct udp_info *info, u64 *key)
{
	struct ipv6hdr ip6;
	struct iphdr ip4;
	void *ip = 0;
	long ret;

	/* For normal IPv4 and IPv6 flows we expect that deleting the element
	 * should be successful. But there is another case where IPv6 socket
	 * sends with an IPv4 destination address. This results in the IPv6
	 * UDP hookpoint udpv6_send() to call the functoin udp_send() which
	 * is also hooked for IPv4 socket sends. The result is we overwrite
	 * the retprobe map entry that had the IPv6 info with the new IPv4
	 * info, because we have the pid/tgid. This is in fact what we want
	 * because now when udp_send() returns we capture all the IPv4 info
	 * and push an event to userspace. But, now when go through the return
	 * path from udpv6_send() there will be no entry in the map so we
	 * get an ENOENT error. This is OK we simply correct the map accounting
	 * by decrementing the counter and let it fall through. Notice we
	 * still want to catch other errors.
	 */
	ret = map_delete_elem(&tg_udp_retprobe_map, key);
	if (ret == -ENOENT) {
		udp_retprobe_map_dec();
	} else if (ret < 0) {
		if (info) {
			if (!info->ipv6) {
				ip4.saddr = info->saddr.ipv4;
				ip4.daddr = info->daddr.ipv4;
				ip = (void *)&ip4;
			} else {
				copy_ipv6_addr((u64 *)&ip6.saddr, info->saddr.ipv6);
				copy_ipv6_addr((u64 *)&ip6.daddr, info->daddr.ipv6);
				ip = (void *)&ip6;
			}
			emit_ip_error_event(ctx, ip, &cookie, info->ipv6,
					    0, 2, 0, IP_ERROR_UDP_RETPROBE_DEL);
		} else {
			emit_ip_error_event(ctx, 0, &cookie, false,
					    0, 2, 0, IP_ERROR_UDP_RETPROBE_DEL);
		}
	} else {
		udp_retprobe_map_dec();
	}
}

/* On the first entry to udp_sendmsg() for a new socket, the
 * socket cookie is empty, so instead of trying to do socket
 * gymnastics here, store the sk and msg and look them up on
 * the return.
 */
static inline __attribute__((always_inline)) int udp_send(struct pt_regs *ctx)
{
	u64 pid_tgid = get_current_pid_tgid();
	struct udp_sock_info *value;
	int zero = 0;

	value = (struct udp_sock_info *)map_lookup_elem(&udp_sock_info_heap, &zero);
	if (!value)
		return 0;

	value->sk = (struct sock *)PT_REGS_PARM1(ctx);
	value->msg = (struct msghdr *)PT_REGS_PARM2(ctx);
	add_to_retprobe_map(ctx, (u64)value->sk, &pid_tgid, value);
	return 0;
}

static inline __attribute__((always_inline)) int
udp_sendret(struct pt_regs *ctx, bool ipv6)
{
	u64 pid_tgid = get_current_pid_tgid();
	struct udp_sock_info *sock_info;
	struct socketmap_value *process;
	struct udp_info_value *value;
	struct udp_info *info = 0;
	int ret = PT_REGS_RC(ctx);
	struct udp_info_key key;
	u32 cookie_ver = 0;
	u64 cookie = 0;
	int zero = 0;
	int hasctx;

	if (ret < 0) {
		del_from_retprobe_map(ctx, cookie, info, &pid_tgid);
		return 0;
	}

	/* IPv6 sockets sending IPv4 UDP packets will return
	 * here and events will be generated by the create IPv4
	 * event. This happens because IPv4 return probe deleted
	 * the context.
	 */
	sock_info = lookup_retprobe_map(ctx, &pid_tgid);
	if (!sock_info) {
		if (!ipv6) {
			/* Only report errors for IPv4 (udp_sendmsg) as IPv6 lookups
			 * could fail as described above (nested IPv4 send deleted
			 * the sock info).
			 */
			emit_ip_error_event(ctx, 0, 0, false,
					    0, 2, 0, IP_ERROR_UDP_SEND_NO_SOCK_INFO);
		}
		return 0;
	}

	write_cookie(&cookie, (u64)sock_info->sk);
	if (!cookie) {
		del_from_retprobe_map(ctx, cookie, info, &pid_tgid);
		emit_ip_error_event(ctx, 0, 0, false,
				    0, 2, 0, IP_ERROR_UDP_SEND_NO_COOKIE);
		return 0;
	}

	process = lookup_socketmap(&cookie);
	if (process)
		cookie_ver = process->version;

	key.ipv6 = ipv6;
	udp_key_daddr_dport(&key, &cookie, cookie_ver, sock_info);

	value = (struct udp_info_value *)map_lookup_elem(&tg_udp_map, &key);
	if (!value) {
		/* Entry was not created by the stack programs.
		 * Create a new entry and update the socket map.
		 */
		value = (struct udp_info_value *)map_lookup_elem(&tg_udp_value_heap, &zero);
		if (!value) {
			del_from_retprobe_map(ctx, cookie, info, &pid_tgid);
			return 0;
		}

		if (!ipv6) {
			info = udp4_get_info(sock_info);
		} else {
			info = udp6_get_info(sock_info);
		}
		if (!info) {
			del_from_retprobe_map(ctx, cookie, info, &pid_tgid);
			return 0;
		}

		udp_info_tx_reset(value, 0);
		if (!ipv6) {
			set_ipv6_addr_from_ipv4(value->saddr, info->saddr.ipv4);
			set_ipv6_addr_from_ipv4(value->daddr, info->daddr.ipv4);
		} else {
			copy_ipv6_addr(value->saddr, info->saddr.ipv6);
			copy_ipv6_addr(value->daddr, info->daddr.ipv6);
		}
		value->ipv6 = ipv6;
		value->sport = info->sport;
		value->dport = info->dport;
		value->skb_consume_misses = 0;
		hasctx = add_process_ctx(value);
		update_submitted_value(value, ret);
		if (hasctx) {
			emit_udp_connect_event(ctx, &cookie, cookie_ver, value);
		} else {
			emit_ip_error_event(ctx, 0, &cookie, ipv6, 0, 2, 0, IP_ERROR_UDP_SEND_MISSING_PROCESS);
		}

		map_update_elem(&tg_udp_map, &key, value, 0);
	} else {
		update_submitted_value(value, ret);
		if (!value->pid) {
			hasctx = add_process_ctx(value);
			if (hasctx) {
				emit_udp_connect_event(ctx, &cookie, cookie_ver, value);
			} else {
				emit_ip_error_event(ctx, 0, &cookie, ipv6, 0, 2, 0, IP_ERROR_UDP_SEND_MISSING_PROCESS);
			}
		}
	}

	/* Ensure we have an up-to-date cookie->process mapping. */
	if (!update_socketmap(&cookie, value->pid, IPPROTO_UDP)) {
		emit_ip_error_event(ctx, 0, &cookie, ipv6, 0, 2, 0, IP_ERROR_UPDATE_SOCKETMAP_NO_PROCESS);
	}

	del_from_retprobe_map(ctx, cookie, info, &pid_tgid);
	return 0;
}

static inline __attribute__((always_inline)) struct udp_info *
udp_get_skb_info(void *ctx, u64 *cookie, struct sk_buff *skb)
{
	struct udp_packet_details *packet;
	u16 network_header_off;
	struct udp_info *info;
	void *skb_head;
	int zero = 0;
	u8 ipver;

	info = (struct udp_info *)map_lookup_elem(&tg_udp_info_heap, &zero);
	if (!info)
		return 0;
	packet = (struct udp_packet_details *)map_lookup_elem(&tg_udp_header_heap, &zero);
	if (!packet)
		return 0;

	ipver = get_ip_version(&network_header_off, &skb_head, skb);
	switch (ipver) {
	case 4:
		if (!get_ip4_header(&packet->ip.ip4, network_header_off,
				    skb_head)) {
			emit_ip_error_event(ctx, 0, cookie, false,
					    ipver, 2, 0, IP_ERROR_UDP_RECV_READ_IP);
			return 0;
		}
		info->ipv6 = false;
		break;
	case 6:
		if (!get_ip6_header(&packet->ip.ip6, network_header_off,
				    skb_head)) {
			emit_ip_error_event(ctx, 0, cookie, true,
					    ipver, 2, 0, IP_ERROR_UDP_RECV_READ_IP);
			return 0;
		}
		info->ipv6 = true;
		break;
	default:
		emit_ip_error_event(ctx, 0, cookie, false,
				    ipver, 2, 0, IP_ERROR_UDP_RECV_NO_VERSION);
		return 0;
	}

	if (!get_udp_header(&packet->udp, 0, skb_head, skb)) {
		emit_ip_error_event(ctx, &packet->ip, cookie, info->ipv6,
				    ipver, 2, 0, IP_ERROR_UDP_RECV_NO_VERSION);
		return 0;
	}

	/* addresses are in network byte order and ports are in host byte order. */
	if (!info->ipv6) {
		info->saddr.ipv4 = packet->ip.ip4.daddr;
		info->daddr.ipv4 = packet->ip.ip4.saddr;
	} else {
		copy_ipv6_addrs_to_info(info, &packet->ip.ip6.daddr,
					&packet->ip.ip6.saddr);
	}
	info->sport = bpf_ntohs(packet->udp.dest);
	info->dport = bpf_ntohs(packet->udp.source);
	info->padding[0] = 0;
	info->padding[1] = 0;
	info->padding[2] = 0;

	return info;
}

static inline __attribute__((always_inline)) bool
udp_set_key(struct udp_info_key *key, u64 *cookie, u32 cookie_ver, void *ctx, struct sk_buff *skb)
{
	struct udp_packet_details *packet;
	u16 network_header_off;
	void *skb_head;
	int zero = 0;
	u8 ipver;

	packet = (struct udp_packet_details *)map_lookup_elem(&tg_udp_header_heap, &zero);
	if (!packet)
		return false;

	ipver = get_ip_version(&network_header_off, &skb_head, skb);
	switch (ipver) {
	case 4:
		if (!get_ip4_header(&packet->ip.ip4, network_header_off,
				    skb_head)) {
			emit_ip_error_event(ctx, 0, &key->cookie, false,
					    ipver, 1, 0, IP_ERROR_UDP_RECV_READ_IP);
			return false;
		}
		key->ipv6 = false;
		break;
	case 6:
		if (!get_ip6_header(&packet->ip.ip6, network_header_off,
				    skb_head)) {
			emit_ip_error_event(ctx, 0, &key->cookie, true,
					    ipver, 1, 0, IP_ERROR_UDP_RECV_READ_IP);
			return false;
		}
		key->ipv6 = true;
		break;
	default:
		emit_ip_error_event(ctx, 0, &key->cookie, false,
				    ipver, 1, 0, IP_ERROR_UDP_RECV_NO_VERSION);
		return false;
	}

	if (!get_udp_header(&packet->udp, 0, skb_head, skb)) {
		emit_ip_error_event(ctx, &packet->ip, &key->cookie, key->ipv6,
				    ipver, 1, 0, IP_ERROR_UDP_RECV_NO_VERSION);
		return false;
	}

	/* addresses are in network byte order and ports are in host byte order. */
	if (!key->ipv6) {
		key->daddr[0] = packet->ip.ip4.saddr;
		key->daddr[1] = 0;
	} else {
		u64 *addr = (u64 *)&packet->ip.ip6.saddr;
		key->daddr[0] = addr[0];
		key->daddr[1] = addr[1];
	}
	key->dport = bpf_ntohs(packet->udp.source);
	key->cookie = *cookie;
	key->padding = 0;
	key->version = cookie_ver;

	return true;
}

/* Call this function if the record lacks the tuple or the PID.
 * Returns true if a connect event should now be sent.
 */
static inline __attribute__((always_inline)) bool
udp_set_info(void *ctx, u64 *cookie, struct udp_info_value *value,
	     struct sk_buff *skb)
{
	struct udp_info *info;

	if (value->saddr[0] == 0 && value->saddr[1] == 0) {
		info = udp_get_skb_info(ctx, cookie, skb);
		if (info) {
			value->ipv6 = info->ipv6;
			if (!info->ipv6) {
				set_ipv6_addr_from_ipv4(value->saddr,
							info->daddr.ipv4);
				set_ipv6_addr_from_ipv4(value->daddr,
							info->saddr.ipv4);
			} else {
				copy_ipv6_addr(value->saddr, info->daddr.ipv6);
				copy_ipv6_addr(value->daddr, info->saddr.ipv6);
			}
			value->sport = info->dport;
			value->dport = info->sport;
		} else {
			update_consume_misses(value);
			value->ipv6 = false;
			value->saddr[0] = 0;
			value->saddr[1] = 0;
			value->daddr[0] = 0;
			value->daddr[1] = 0;
			value->sport = 0;
			value->dport = 0;
		}
	}

	if (value->saddr[0] != 0 || value->saddr[1] != 0)
		return true;

	return false;
}

/* UDP data is consumed on a datagram-by-datagram basis; every recv(),
 * recvfrom() and read() on a UDP file descriptor results in the
 * consumption of a single datagram. If the requested volume of data
 * is >= the datagram payload size, then the whole datagram is provided
 * and the payload size is returned.
 * If the requested volume is < the datagram payload size, then the
 * requested volume is provided. In the usual case, the size requested
 * is returned; if the MSG_TRUNC flag is specified, the payload size is
 * returned instead.
 * This function is attached to skb_consume_udp() which occurs late in
 * udp_recvmsg() and udp6_recvmsg(). The length parameter provided to
 * it is the size requested (capped at payload size) if MSG_TRUNC wasn't
 * specified, or the payload size if MSG_TRUNC was specified.
 * This value is the closest approximation to the volume of data consumed,
 * as the length parameter to udp[v6]_recvmsg() is a buffer size, not a
 * payload length (as are all the length parameters that led to this
 * function being called, e.g. recv() syscall); and the length parameter
 * to skb_consume_udp() either specifies the amount of data to consume
 * (MSG_TRUNC not set, capped at payload size) or the payload size
 * (MSG_TRUNC is set) because the application wants to know how much
 * data it could have consumed. In both cases, remaining data in the
 * datagram is discarded, so we can treat it as consumed in the second
 * case, as the application is at least aware of it.
 * Aside from this impassioned argument, there is no more accurate place
 * to hook!
 */
static inline __attribute__((always_inline)) int udp_recv(struct pt_regs *ctx)
{
	struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	int len = (int)PT_REGS_PARM3(ctx);
	struct socketmap_value *process;
	struct udp_info_value *value;
	struct udp_info_key *key;
	int valid_addr = 0;
	u32 cookie_ver = 0;
	int hasctx = 1;
	int zero = 0;
	u64 cookie;

	/* Disregard peeks */
	if (len <= 0)
		return 0;

	/* We need a cookie to attach this datagram to */
	write_cookie(&cookie, (u64)sk);
	if (!cookie) {
		emit_ip_error_event(ctx, 0, 0, false,
				    0, 1, 0, IP_ERROR_UDP_RECV_NO_COOKIE);
		return 0;
	}

	key = (struct udp_info_key *)map_lookup_elem(&tg_udp_key_heap, &zero);
	if (!key)
		return 0;

	process = lookup_socketmap(&cookie);
	if (process)
		cookie_ver = process->version;

	if (!udp_set_key(key, &cookie, cookie_ver, ctx, skb)) {
		key->daddr[0] = 0;
		key->daddr[1] = 0;
		key->ipv6 = 0;
		key->dport = 0;
		key->cookie = cookie;
		key->version = 0;
	}

	value = (struct udp_info_value *)map_lookup_elem(&tg_udp_map, key);
	if (!value) {
		/* Entry was not created by the stack programs.
		 * Create a new entry and update the socket map.
		 * Should be a rare occurrence.
		 */
		value = (struct udp_info_value *)map_lookup_elem(&tg_udp_value_heap, &zero);
		if (!value)
			return 0;

		udp_info_consumed_reset(value, len);
		value->skb_consume_misses = 0;

		hasctx = add_process_ctx(value);
		if (!hasctx) {
			emit_ip_error_event(ctx, 0, &cookie, key->ipv6, 0, 1, 0, IP_ERROR_UDP_RECV_MISSING_PROCESS);
		}
		valid_addr = udp_set_info(ctx, &cookie, value, skb);

		if (hasctx && valid_addr) {
			emit_udp_connect_event(ctx, &cookie, cookie_ver, value);
		}
		map_update_elem(&tg_udp_map, key, value, 0);
	} else {
		update_consumed_value(value, len);
		if ((value->saddr[0] == 0 && value->saddr[1] == 0) ||
		    value->pid == 0) {
			if (value->pid == 0) {
				hasctx = add_process_ctx(value);
				if (!hasctx) {
					emit_ip_error_event(ctx, 0, &cookie, key->ipv6, 0, 1, 0, IP_ERROR_UDP_RECV_MISSING_PROCESS);
				}
			}
			valid_addr = udp_set_info(ctx, &cookie, value, skb);

			if (hasctx && valid_addr) {
				emit_udp_connect_event(ctx, &cookie, cookie_ver, value);
			}
		}
	}
	/* Ensure we have an up-to-date cookie->process mapping. */
	if (!update_socketmap(&cookie, value->pid, IPPROTO_UDP)) {
		emit_ip_error_event(ctx, 0, &cookie, key->ipv6, 0, 1, 0, IP_ERROR_UPDATE_SOCKETMAP_NO_PROCESS);
	}

	return 0;
}

#endif
