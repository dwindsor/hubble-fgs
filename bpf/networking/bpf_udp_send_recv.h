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

struct bpf_map_def __attribute__((section("maps"), used)) udp_retprobe_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(struct udp_sock_info),
	.max_entries = 1024,
};

struct bpf_map_def __attribute__((section("maps"), used)) udp_sock_info_heap = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(struct udp_sock_info),
	.max_entries = 1,
};

static inline __attribute__((always_inline)) void
check_and_send_payload(void *ctx, u64 *cookie, struct udp_info_value *value)
{
	struct msg_ipv4_udp_event *ev;
	size_t size;
	struct udp_sensor_config *config;
	int zero = 0;

	config = map_lookup_elem(&udp_config_map, &zero);
	if (!config)
		return;

	if (config->dnsPorts[0] == 0 ||
	    !dns_port_match(config->dnsPorts, value->sport,
			    bpf_ntohs(value->dport)))
		return;

	/* Cheap lookup to see if the cookie is likely in the payload_map.
	 * This returns true if a cookie with the same LSBs has been added
	 * to the map, and false otherwise. False positives are possible
	 * (and expected), but false negatives will never happen. Therefore,
	 * sometimes we will look up in the real map when the cookie isn't
	 * in there, but will save ourselves many look ups when the cookie
	 * definitely isn't in there.
	 * The only times the cookie shouldn't be in the map, after passing
	 * the DNS ports check, is in kernels >=5.10 where the DNS payload
	 * has already been transmitted by the stack programs.
	 */
	if (!lookup_udp_payload_bloom(*cookie))
		return;

	ev = map_lookup_elem(&udp_payload_map, cookie);
	if (!ev)
		return;

	ev->event.key.pid = value->pid;
	ev->event.key.ktime = value->pid_ktime;

	size = ev->event.common.size;
	if (size <= sizeof(*ev)) {
		perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, ev,
				  size);
	}

	if (map_delete_elem(&udp_payload_map, cookie) == 0) {
		dec_udp_payload_map();
		remove_from_udp_payload_bloom(*cookie);
	}
}

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
	if (in && namelen >= sizeof(*in)) {
		probe_read(&info->daddr, sizeof(u32),
			   _(&(in->sin_addr.s_addr)));
		probe_read(&info->dport, sizeof(u16), _(&(in->sin_port)));
	} else {
		probe_read(&info->daddr, sizeof(u32),
			   _(&(sk->__sk_common.skc_daddr)));
		probe_read(&info->dport, sizeof(u16),
			   _(&(sk->__sk_common.skc_dport)));
	}
	probe_read(&info->saddr, sizeof(u32), _(&(inet->inet_saddr)));
	probe_read(&info->sport, sizeof(u16), _(&(inet->inet_sport)));
	info->padding = 0;
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

	process = event_find_curr(&ppid, 0, &walker);
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
static inline __attribute__((always_inline)) int udp4_send(struct pt_regs *ctx)
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
udp4_sendret(struct pt_regs *ctx, bool lazy)
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
	if (!sock_info)
		return 0;

	write_cookie_from_sk(&cookie, sock_info->sk, lazy);
	if (!cookie) {
		map_delete_elem(&udp_retprobe_map, &pid_tgid);
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

		info = udp4_get_info(sock_info);
		if (!info) {
			map_delete_elem(&udp_retprobe_map, &pid_tgid);
			return 0;
		}

		udp_info_tx_reset(value, 0);
		value->saddr = info->saddr;
		value->daddr = info->daddr;
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
		check_and_send_payload(ctx, &cookie, value);
	}

	/* Ensure we have an up-to-date cookie->process mapping. */
	update_cookie_proc_map(&cookie, value->pid);

	map_delete_elem(&udp_retprobe_map, &pid_tgid);
	return 0;
}

static inline __attribute__((always_inline)) struct udp_info *
udp4_get_skb_info(struct sk_buff *skb)
{
	struct udp_info *info;
	int zero = 0;

	struct udphdr udph;
	struct iphdr iph;
	void *skb_head;

	info = map_lookup_elem(&udp_info_heap, &zero);
	if (!info)
		return 0;

	if (!get_ip4_header(&iph, &skb_head, skb))
		return 0;
	if (!get_udp4_header(&udph, 0, skb_head, skb))
		return 0;

	/* skb values are in network byte order and to be consistent across
	 * sock generated keys and packet generated values we byte swap the
	 * source port to be in host byte order, aligning with socket
	 * struct.
	 */
	info->saddr = iph.daddr;
	info->daddr = iph.saddr;
	info->sport = bpf_ntohs(udph.dest);
	info->dport = udph.source;
	info->padding = 0;

	return info;
}

/* Call this function if the record lacks the tuple or the PID.
 * Returns true if a connect event should now be sent.
 */
static inline __attribute__((always_inline)) bool
udp4_set_info(struct udp_info_value *value, struct sk_buff *skb)
{
	struct udp_info *info;
	int hasctx = 1;

	if (value->pid == 0) {
		hasctx = add_process_ctx(value);
	}

	if (value->saddr == 0) {
		info = udp4_get_skb_info(skb);
		if (info) {
			value->saddr = info->daddr;
			value->daddr = info->saddr;
			value->sport = info->dport;
			value->dport = info->sport;
		} else {
			update_consume_misses(value);
			value->saddr = 0;
			value->daddr = 0;
			value->sport = 0;
			value->dport = 0;
		}
	}

	if (hasctx && value->saddr != 0)
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
static inline __attribute__((always_inline)) int udp4_recv(struct pt_regs *ctx,
							   bool lazy)
{
	u64 pid_tgid = get_current_pid_tgid();
	struct udp_info_value *value;
	int zero = 0;
	struct sock *sk = (void *)ctx->di;
	struct sk_buff *skb = (void *)ctx->si;
	int len = (int)ctx->dx;
	u64 cookie;

	/* Disregard peeks */
	if (len <= 0) {
		map_delete_elem(&udp_retprobe_map, &pid_tgid);
		return 0;
	}

	/* We need a cookie to attach this datagram to */
	write_cookie_from_sk(&cookie, sk, lazy);
	if (!cookie) {
		return 0;
	}

	value = map_lookup_elem(&udp_map, &cookie);
	if (!value) {
		/* Entry was not created by the stack programs.
		 * Create a new entry and update the socket map.
		 * Should be a rare occurrence.
		 */
		value = map_lookup_elem(&udp_value_heap, &zero);
		if (!value) {
			map_delete_elem(&udp_retprobe_map, &pid_tgid);
			return 0;
		}

		udp_info_consumed_reset(value, len);
		value->skb_consume_misses = 0;

		if (udp4_set_info(value, skb)) {
			emit_udp_connect_event(ctx, value);
		}
		map_update_elem(&udp_map, &cookie, value, 0);
	} else {
		update_consumed_value(value, len);
		if (value->saddr == 0 || value->pid == 0) {
			if (udp4_set_info(value, skb)) {
				emit_udp_connect_event(ctx, value);
			}
		}
		check_and_send_payload(ctx, &cookie, value);
	}
	/* Ensure we have an up-to-date cookie->process mapping.
	 */
	update_cookie_proc_map(&cookie, value->pid);

	map_delete_elem(&udp_retprobe_map, &pid_tgid);
	return 0;
}
