#include "vmlinux.h"

#include "api.h"
#include "hubble_msg.h"
#include "bpf_events.h"
#include "bpf_udp.h"
#include "cookie.h"
#include "bpf_network_helpers.h"

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
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, struct udp_sock_info);
	__uint(max_entries, 1024);
} udp_retprobe_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct udp_sock_info);
	__uint(max_entries, 1);
} udp_sock_info_heap SEC(".maps");

static inline __attribute__((always_inline)) struct udp_info *
udp4_get_info(struct udp_sock_info *sock_info)
{
	struct sock *sk = sock_info->sk;
	struct inet_sock *inet = (void *)sk;
	struct msghdr *msg = sock_info->msg;
	struct sockaddr_in *in;
	int namelen;

	struct udp_info *info;
	int zero = 0;

	info = map_lookup_elem(&udp_info_heap, &zero);
	if (!info)
		return 0;

	probe_read(&in, sizeof(void *), _(&(msg->msg_name)));
	probe_read(&namelen, sizeof(int), _(&(msg->msg_namelen)));
	info->ipv6 = false;
	if (in && namelen >= sizeof(*in)) {
		probe_read(&info->daddr.ipv4, sizeof(u32),
			   _(&(in->sin_addr.s_addr)));
		probe_read(&info->dport, sizeof(u16), _(&(in->sin_port)));
	} else {
		probe_read(&info->daddr.ipv4, sizeof(u32),
			   _(&(sk->__sk_common.skc_daddr)));
		probe_read(&info->dport, sizeof(u16),
			   _(&(sk->__sk_common.skc_dport)));
	}
	probe_read(&info->saddr.ipv4, sizeof(u32), _(&(inet->inet_saddr)));
	probe_read(&info->sport, sizeof(u16), _(&(inet->inet_sport)));
	info->padding[0] = 0;
	info->padding[1] = 0;
	info->padding[2] = 0;
	/* Values are expected to be in network byte order with source port
	 * in host byte order.
	 */
	info->sport = bpf_ntohs(info->sport);

	return info;
}

static inline __attribute__((always_inline)) struct udp_info *
udp6_get_info(struct udp_sock_info *sock_info)
{
	struct sock *sk = sock_info->sk;
	struct inet_sock *inet = (void *)sk;
	struct ipv6_pinfo *pinet6;
	struct msghdr *msg = sock_info->msg;
	struct sockaddr_in6 *in;
	int namelen;
	struct udp_info *info;
	int zero = 0;

	info = map_lookup_elem(&udp_info_heap, &zero);
	if (!info)
		return 0;

	probe_read(&in, sizeof(void *), _(&(msg->msg_name)));
	probe_read(&namelen, sizeof(int), _(&(msg->msg_namelen)));
	if (in && namelen >= sizeof(*in)) {
		probe_read(&info->daddr, sizeof(struct in6_addr),
			   _(&(in->sin6_addr)));
		probe_read(&info->dport, sizeof(u16), _(&(in->sin6_port)));
	} else {
		probe_read(&info->daddr, sizeof(struct in6_addr),
			   _(&(sk->__sk_common.skc_v6_daddr)));
		probe_read(&info->dport, sizeof(u16),
			   _(&(sk->__sk_common.skc_dport)));
	}
	probe_read(&pinet6, sizeof(struct ipv6_pinfo *), _(&(inet->pinet6)));
	probe_read(&info->saddr, sizeof(struct in6_addr), _(&(pinet6->saddr)));
	probe_read(&info->sport, sizeof(u16), _(&(inet->inet_sport)));
	info->ipv6 = true;
	info->padding[0] = 0;
	info->padding[1] = 0;
	info->padding[2] = 0;
	/* Values are expected to be in network byte order with source port
	 * in host byte order.
	 */
	info->sport = bpf_ntohs(info->sport);

	return info;
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

	value = map_lookup_elem(&udp_sock_info_heap, &zero);
	if (!value)
		return 0;

	value->sk = (void *)ctx->di;
	value->msg = (void *)ctx->si;
	map_update_elem(&udp_retprobe_map, &pid_tgid, value, 0);
	return 0;
}

static inline __attribute__((always_inline)) int
udp_sendret(struct pt_regs *ctx, bool lazy, bool ipv6)
{
	u64 pid_tgid = get_current_pid_tgid();
	struct udp_sock_info *sock_info;
	struct udp_info *info;
	struct udp_info_value *value;
	int hasctx;
	int ret = ctx->ax;
	u64 cookie;
	int zero = 0;

	if (ret < 0) {
		map_delete_elem(&udp_retprobe_map, &pid_tgid);
		return 0;
	}

	sock_info = map_lookup_elem(&udp_retprobe_map, &pid_tgid);
	if (!sock_info) {
		emit_ip_error_event(ctx, 0, 0, false,
				    IP_ERROR_UDP_SEND_NO_SOCK_INFO);
		return 0;
	}

	write_cookie_from_sk(&cookie, sock_info->sk, lazy);
	if (!cookie) {
		map_delete_elem(&udp_retprobe_map, &pid_tgid);
		emit_ip_error_event(ctx, 0, 0, false,
				    IP_ERROR_UDP_SEND_NO_COOKIE);
		return 0;
	}

	value = map_lookup_elem(&udp_map, &cookie);
	if (!value) {
		/* Entry was not created by the stack programs.
		 * Create a new entry and update the socket map.
		 */
		value = map_lookup_elem(&udp_value_heap, &zero);
		if (!value) {
			map_delete_elem(&udp_retprobe_map, &pid_tgid);
			return 0;
		}

		if (!ipv6) {
			info = udp4_get_info(sock_info);
		} else {
			info = udp6_get_info(sock_info);
		}
		if (!info) {
			map_delete_elem(&udp_retprobe_map, &pid_tgid);
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
			emit_udp_connect_event(ctx, value);
		}

		map_update_elem(&udp_map, &cookie, value, 0);
	} else {
		update_submitted_value(value, ret);
		if (!value->pid) {
			hasctx = add_process_ctx(value);
			if (hasctx) {
				emit_udp_connect_event(ctx, value);
			}
		}
	}

	/* Ensure we have an up-to-date cookie->process mapping. */
	update_socketmap(&cookie, 0, value->pid);

	map_delete_elem(&udp_retprobe_map, &pid_tgid);
	return 0;
}

static inline __attribute__((always_inline)) struct udp_info *
udp_get_skb_info(void *ctx, u64 *cookie, struct sk_buff *skb)
{
	struct udp_info *info;
	int zero = 0;
	u16 network_header_off;

	struct udp_packet_details *packet;
	void *skb_head;
	u8 ipver;

	info = map_lookup_elem(&udp_info_heap, &zero);
	if (!info)
		return 0;
	packet = map_lookup_elem(&udp_header_heap, &zero);
	if (!packet)
		return 0;

	ipver = get_ip_version(&network_header_off, &skb_head, skb);
	switch (ipver) {
	case 4:
		if (!get_ip4_header(&packet->ip.ip4, network_header_off,
				    skb_head)) {
			emit_ip_error_event(ctx, 0, cookie, false,
					    IP_ERROR_UDP_RECV_READ_IP);
			return 0;
		}
		info->ipv6 = false;
		break;
	case 6:
		if (!get_ip6_header(&packet->ip.ip6, network_header_off,
				    skb_head)) {
			emit_ip_error_event(ctx, 0, cookie, true,
					    IP_ERROR_UDP_RECV_READ_IP);
			return 0;
		}
		info->ipv6 = true;
		break;
	default:
		emit_ip_error_event(ctx, 0, cookie, false,
				    IP_ERROR_UDP_RECV_NO_VERSION);
		return 0;
	}

	if (!get_udp_header(&packet->udp, 0, skb_head, skb)) {
		emit_ip_error_event(ctx, &packet->ip, cookie, info->ipv6,
				    IP_ERROR_UDP_RECV_NO_VERSION);
		return 0;
	}

	/* skb values are in network byte order and to be consistent across
	 * sock generated keys and packet generated values we byte swap the
	 * source port to be in host byte order, aligning with socket
	 * struct.
	 */
	if (!info->ipv6) {
		info->saddr.ipv4 = packet->ip.ip4.daddr;
		info->daddr.ipv4 = packet->ip.ip4.saddr;
	} else {
		copy_ipv6_addrs_to_info(info, &packet->ip.ip6.daddr,
					&packet->ip.ip6.saddr);
	}
	info->sport = bpf_ntohs(packet->udp.dest);
	info->dport = packet->udp.source;
	info->padding[0] = 0;
	info->padding[1] = 0;
	info->padding[2] = 0;

	return info;
}

/* Call this function if the record lacks the tuple or the PID.
 * Returns true if a connect event should now be sent.
 */
static inline __attribute__((always_inline)) bool
udp_set_info(void *ctx, u64 *cookie, struct udp_info_value *value,
	     struct sk_buff *skb)
{
	struct udp_info *info;
	int hasctx = 1;

	if (value->pid == 0) {
		hasctx = add_process_ctx(value);
	}

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

	if (hasctx && (value->saddr[0] != 0 || value->saddr[1] != 0))
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
static inline __attribute__((always_inline)) int udp_recv(struct pt_regs *ctx,
							  bool lazy)
{
	struct udp_info_value *value;
	int zero = 0;
	struct sock *sk = (void *)ctx->di;
	struct sk_buff *skb = (void *)ctx->si;
	int len = (int)ctx->dx;
	u64 cookie;

	/* Disregard peeks */
	if (len <= 0)
		return 0;

	/* We need a cookie to attach this datagram to */
	write_cookie_from_sk(&cookie, sk, lazy);
	if (!cookie) {
		emit_ip_error_event(ctx, 0, 0, false,
				    IP_ERROR_UDP_RECV_NO_COOKIE);
		return 0;
	}

	value = map_lookup_elem(&udp_map, &cookie);
	if (!value) {
		/* Entry was not created by the stack programs.
		 * Create a new entry and update the socket map.
		 * Should be a rare occurrence.
		 */
		value = map_lookup_elem(&udp_value_heap, &zero);
		if (!value)
			return 0;

		udp_info_consumed_reset(value, len);
		value->skb_consume_misses = 0;

		if (udp_set_info(ctx, &cookie, value, skb)) {
			emit_udp_connect_event(ctx, value);
		}
		map_update_elem(&udp_map, &cookie, value, 0);
	} else {
		update_consumed_value(value, len);
		if ((value->saddr[0] == 0 && value->saddr[1] == 0) ||
		    value->pid == 0) {
			if (udp_set_info(ctx, &cookie, value, skb)) {
				emit_udp_connect_event(ctx, value);
			}
		}
	}
	/* Ensure we have an up-to-date cookie->process mapping.
	 */
	update_socketmap(&cookie, 0, value->pid);

	return 0;
}
