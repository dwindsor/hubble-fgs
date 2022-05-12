#include "vmlinux.h"

#include "api.h"
#include "hubble_msg.h"
#include "bpf_events.h"
#include "bpf_udp.h"
#include "cookie.h"
#include "bpf_network_helpers.h"

char _license[] __attribute__((section(("license")), used)) = "GPL";
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
	u64 *cookie;
	int zero = 0;

	if (ret < 0) {
		map_delete_elem(&udp_retprobe_map, &pid_tgid);
		return 0;
	}

	sock_info = map_lookup_elem(&udp_retprobe_map, &pid_tgid);
	if (!sock_info)
		return 0;

	cookie = map_lookup_elem(&udp_cookie_heap, &zero);
	if (!cookie) {
		map_delete_elem(&udp_retprobe_map, &pid_tgid);
		return 0;
	}
	write_cookie_from_sk(cookie, sock_info->sk, lazy);
	if (!*cookie) {
		map_delete_elem(&udp_retprobe_map, &pid_tgid);
		return 0;
	}

	value = map_lookup_elem(&udp_map, cookie);
	if (!value) {
		/* Entry was not created by the stack programs.
		 * Create a new entry and update the socket map.
		 */
		int zero = 0;

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

		map_update_elem(&udp_map, cookie, value, 0);
	} else {
		update_submitted_value(value, ret);
		if (!value->pid) {
			hasctx = add_process_ctx(value);
			if (hasctx) {
				emit_udp_connect_event(ctx, value);
				/* DNS payloads are only available in non-lazy kernels.
				 * If there is a payload waiting, that means it was
				 * generated before the cookie->process mapping existed.
				 * Complete the process info and send it.
				 */
				if (!lazy)
					check_and_send_payload(ctx, cookie,
							       value);
			}
		}
	}

	/* Ensure we have an up-to-date cookie->process mapping. */
	update_cookie_proc_map(cookie, value->pid);

	map_delete_elem(&udp_retprobe_map, &pid_tgid);
	return 0;
}

static inline __attribute__((always_inline)) struct udp_info *
udp4_get_skb_info(struct sk_buff *skb, int *len)
{
	struct udp_info *info;
	int zero = 0;

	struct udphdr udph;
	struct iphdr iph;

	info = map_lookup_elem(&udp_info_heap, &zero);
	if (!info)
		return 0;

	if (!get_udp4_headers(&iph, &udph, skb))
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

	if (udph.len < sizeof(udph))
		return 0;

	*len = bpf_ntohs(udph.len) - sizeof(udph);

	return info;
}

/* On entry to __skb_recv_udp(), check if it's a genuine read (not just a
 * peek), and store the sk for the return.
 */
static inline __attribute__((always_inline)) int udp4_recv(struct pt_regs *ctx)
{
	u64 pid_tgid = get_current_pid_tgid();
	struct udp_sock_info *value;
	int zero = 0;
	int flags = ctx->si;

	/* Avoid any calls where the packet isn't actually consumed */
	if (flags & MSG_PEEK)
		return 0;

	value = map_lookup_elem(&udp_sock_info_heap, &zero);
	if (!value)
		return 0;

	value->sk = (void *)ctx->di;

	map_update_elem(&udp_retprobe_map, &pid_tgid, value, 0);
	return 0;
}

/* On return of __skb_recv_udp(), check the returned skb is a valid
 * pointer, and retrieve the stored sk.
 */
static inline __attribute__((always_inline)) int
udp4_recvret(struct pt_regs *ctx, bool lazy)
{
	u64 pid_tgid = get_current_pid_tgid();
	struct udp_sock_info *sock_info;
	struct udp_info_value *value;
	struct udp_info *info;
	int hasctx, zero = 0;
	int len = 0;
	struct sock *sk;
	struct sk_buff *skb = (void *)ctx->ax;
	u64 *cookie;

	if (!skb) {
		map_delete_elem(&udp_retprobe_map, &pid_tgid);
		return 0;
	}

	sock_info = map_lookup_elem(&udp_retprobe_map, &pid_tgid);
	if (!sock_info)
		return 0;

	sk = sock_info->sk;

	cookie = map_lookup_elem(&udp_cookie_heap, &zero);
	if (!cookie) {
		map_delete_elem(&udp_retprobe_map, &pid_tgid);
		return 0;
	}
	write_cookie_from_sk(cookie, sk, lazy);
	if (!*cookie) {
		map_delete_elem(&udp_retprobe_map, &pid_tgid);
		return 0;
	}

	info = udp4_get_skb_info(skb, &len);
	value = map_lookup_elem(&udp_map, cookie);
	if (!value) {
		/* Entry was not created by the stack programs.
		 * Create a new entry and update the socket map.
		 */
		value = map_lookup_elem(&udp_value_heap, &zero);
		if (!value) {
			map_delete_elem(&udp_retprobe_map, &pid_tgid);
			return 0;
		}

		udp_info_consumed_reset(value, len);

		if (info) {
			value->saddr = info->saddr;
			value->daddr = info->daddr;
			value->sport = info->sport;
			value->dport = info->dport;
			value->skb_consume_misses = 0;
			hasctx = add_process_ctx(value);
			if (hasctx) {
				emit_udp_connect_event(ctx, value);
			}
		} else {
			value->skb_consume_misses = 1;
		}
		map_update_elem(&udp_map, cookie, value, 0);
	} else {
		if (info) {
			update_consumed_value(value, len);
		} else {
			update_consume_misses(value);
		}
		if (!value->pid) {
			/* This can happen when sock_create does not
			 * find a pid because the socket is attached
			 * to a pid that is not a thread group id
			 * leader. In this case we update to proper
			 * pid when we get called from a context that
			 * has probe_read() available. Namely, the
			 * recv side with user context.
			 */
			hasctx = add_process_ctx(value);
			if (hasctx) {
				emit_udp_connect_event(ctx, value);
				/* DNS payloads are only available in non-lazy kernels.
				 * If there is a payload waiting, that means it was
				 * generated before the cookie->process mapping existed.
				 * Complete the process info and send it.
				 */
				if (!lazy)
					check_and_send_payload(ctx, cookie,
							       value);
			}
		}
	}
	/* Ensure we have an up-to-date cookie->process mapping.
	 */
	update_cookie_proc_map(cookie, value->pid);

	map_delete_elem(&udp_retprobe_map, &pid_tgid);
	return 0;
}
