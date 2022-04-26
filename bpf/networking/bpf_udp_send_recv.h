#include "vmlinux.h"

#ifndef bpf_map_def
struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};
#endif

#include "api.h"
#include "hubble_msg.h"
#include "bpf_events.h"
#include "bpf_udp.h"
#include "cookie.h"

char _license[] __attribute__((section(("license")), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

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

static inline __attribute__((always_inline)) struct udp_info *
udp4_get_info(struct udp_sock_info *sock_info, bool lazy)
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
	if (lazy) {
		/* A unique key is needed to identify flows, but without a cookie value
		* its possible to have the same tuple on different processes, and its
		* also possible that some elements of the tuple will be unknown at this
		* point, leading to complexities in accurately identifying the socket
		* by tuple. In these cases we use the sk addr for the cookie. It's not
		* entirely unique because the sk addr might be reused later, but we can
		* mitigate this by updating sk entries when sockets are created.
		*/
		write_cookie(info, (u64)sk);
	} else {
		info->cookie = get_cookie(sk);
	}
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

static inline __attribute__((always_inline)) void
update_tx_counters(struct udp_info_value *value, int bytes)
{
	__sync_fetch_and_add(&value->submitted_bytes, bytes);
	__sync_fetch_and_add(&value->submitted_segs, 1);
	WRITE_ONCE(value->ktime, ktime_get_ns());
}

/* On the first entry to udp_sendmsg() for a new socket, the
 * socket cookie is empty, so instead of trying to do socket
 * gymnastics here, store the sk and msg and look them up on
 * the return.
 */
static inline __attribute__((always_inline)) int udp4_send(struct pt_regs *ctx)
{
	u64 pid = get_current_pid_tgid();
	struct udp_sock_info *value;
	int zero = 0;

	value = map_lookup_elem(&udp_sock_info_heap, &zero);
	if (!value)
		return 0;

	value->sk = (void *)ctx->di;
	value->msg = (void *)ctx->si;
	map_update_elem(&udp_retprobe_map, &pid, value, 0);
	return 0;
}

static inline __attribute__((always_inline)) int
udp4_sendret(struct pt_regs *ctx, bool lazy)
{
	u64 pid = get_current_pid_tgid();
	struct udp_sock_info *sock_info;
	struct udp_info *info;
	struct udp_info_value *value;
	int hasctx;
	struct execve_map_value *execve_value;
	int ret = ctx->ax;

	if (ret < 0) {
		map_delete_elem(&udp_retprobe_map, &pid);
		return 0;
	}

	sock_info = map_lookup_elem(&udp_retprobe_map, &pid);
	if (!sock_info)
		return 0;

	info = udp4_get_info(sock_info, lazy);
	if (!info) {
		map_delete_elem(&udp_retprobe_map, &pid);
		return 0;
	}

	value = map_lookup_elem(&udp_map, &info->cookie);
	if (!value) {
		/* Entry was not created by the stack programs.
		 * This happens on older kernels where sock_create doesn't
		 * allocate a sk. In lieu of finding a better place to hook
		 * socket creation that does allocate a sk, create a new
		 * entry and update the socket map.
		 */
		int zero = 0;

		value = map_lookup_elem(&udp_value_heap, &zero);
		if (!value) {
			map_delete_elem(&udp_retprobe_map, &pid);
			return 0;
		}
		udp_info_tx_reset(value, 0);
		value->saddr = info->saddr;
		value->daddr = info->daddr;
		value->sport = info->sport;
		value->dport = info->dport;
		value->padding = 0;
		hasctx = add_process_ctx(value);
		update_tx_counters(value, ret);
		if (hasctx) {
			emit_udp_connect_event(ctx, value);
			execve_value = execve_map_get(value->pid);
			if (execve_value && execve_value->key.ktime != 0) {
				map_update_elem(&socket_cookie_to_proc_map,
						&info->cookie, execve_value, 0);
			}
		}

		map_update_elem(&udp_map, &info->cookie, value, 0);
	} else {
		update_tx_counters(value, ret);
		if (!value->pid) {
			hasctx = add_process_ctx(value);
			if (hasctx) {
				emit_udp_connect_event(ctx, value);
				execve_value = execve_map_get(value->pid);
				if (execve_value &&
				    execve_value->key.ktime != 0) {
					map_update_elem(
						&socket_cookie_to_proc_map,
						&info->cookie, execve_value, 0);
				}
			}
		}
	}

	/* Ensure we have an up-to-date cookie->process mapping as
	* watermarks relies on it, and if we don't have cgroup/sock_create
	* then this won't be automatically populated.
	*/
	update_cookie_proc_map(info->cookie, value->pid);

	map_delete_elem(&udp_retprobe_map, &pid);
	return 0;
}

static inline __attribute__((always_inline)) struct udp_info *
udp4_get_skb_info(struct pt_regs *ctx, int *len, bool lazy)
{
	u16 transport_header, network_header;
	struct sk_buff *skb = (void *)ctx->si;
	struct sock *sk = (void *)ctx->di;
	struct udp_info *info;
	int zero = 0;

	struct udphdr udph;
	struct iphdr iph;
	void *skb_head;

	info = map_lookup_elem(&udp_info_heap, &zero);
	if (!info)
		return 0;

	probe_read(&transport_header, sizeof(u16), _(&skb->transport_header));
	probe_read(&network_header, sizeof(u16), _(&skb->network_header));

	probe_read(&skb_head, sizeof(void *), _(&skb->head));
	probe_read(&iph, sizeof(iph), skb_head + network_header);
	probe_read(&udph, sizeof(udph), skb_head + transport_header);

	/* skb values are in network byte order and to be consistent across
	 * sock generated keys and packet generated values we byte swap the
	 * source port to be in host byte order, aligning with socket
	 * struct.
	 */
	info->saddr = iph.daddr;
	info->daddr = iph.saddr;
	info->sport = bpf_ntohs(udph.dest);
	info->dport = udph.source;
	if (lazy) {
		write_cookie(info, (u64)sk);
	} else {
		info->cookie = get_cookie(sk);
	}
	info->padding = 0;

	*len = bpf_ntohs(udph.len) - sizeof(udph);

	return info;
}

static inline __attribute__((always_inline)) int udp4_recv(struct pt_regs *ctx,
							   bool lazy)
{
	struct udp_info_value *value;
	struct udp_info *info;
	int hasctx, zero = 0;
	struct execve_map_value *execve_value;
	int len;
	int givenlen = ctx->dx;

	info = udp4_get_skb_info(ctx, &len, lazy);
	if (!info)
		return 0;

	value = map_lookup_elem(&udp_map, &info->cookie);
	if (!value) {
		/* Entry was not created by the stack programs.
		 * This happens on older kernels where sock_create doesn't
		 * allocate a sk. In lieu of finding a better place to hook
		 * socket creation that does allocate a sk, create a new
		 * entry and update the socket map.
		 */
		value = map_lookup_elem(&udp_value_heap, &zero);
		if (!value)
			return 0;

		/* We only consume the packet when givenlen > 0. Values
		 * < 0 represent calls to select() or similar that don't
		 * actually process the packet.
		 */
		if (givenlen > 0) {
			udp_info_consumed_reset(value, len);
		} else {
			udp_info_consumed_reset(value, 0);
		}
		value->saddr = info->saddr;
		value->daddr = info->daddr;
		value->sport = info->sport;
		value->dport = info->dport;
		value->padding = 0;
		hasctx = add_process_ctx(value);
		map_update_elem(&udp_map, &info->cookie, value, 0);
		if (hasctx) {
			emit_udp_connect_event(ctx, value);
			execve_value = execve_map_get(value->pid);
			if (execve_value && execve_value->key.ktime != 0) {
				map_update_elem(&socket_cookie_to_proc_map,
						&info->cookie, execve_value, 0);
			}
		}
	} else {
		/* We only consume the packet when givenlen > 0. Values
		 * < 0 represent calls to select() or similar that don't
		 * actually process the packet.
		 */
		if (givenlen > 0) {
			update_consumed_value(value, len);
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
				execve_value = execve_map_get(value->pid);
				if (execve_value &&
				    execve_value->key.ktime != 0) {
					map_update_elem(
						&socket_cookie_to_proc_map,
						&info->cookie, execve_value, 0);
				}
			}
		}
	}
	/* Ensure we have an up-to-date cookie->process mapping as
	 * watermarks relies on it, and if we don't have cgroup/sock_create
	 * then this won't be automatically populated.
	 */
	update_cookie_proc_map(info->cookie, value->pid);

	return 0;
}
