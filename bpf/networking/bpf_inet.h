#ifndef __BPF_INET_H_
#define __BPF_INET_H_

#define SOCK_CTX

#include "api.h"
#include "hubble_msg.h"
#include "bpf_events.h"
#include "bpf_udp.h"
#include "bpf_burst_process.h"
#include "cookie.h"

struct udp_sensor_config {
	u16 dnsPorts[4];
	u64 watermark_enable;
	u64 watermark_avg_window_size_ms;
	u64 watermark_window_size;
	u64 watermark_trigger_percent;
};

struct bpf_map_def __attribute__((section("maps"), used)) udp_config_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(struct udp_sensor_config),
	.max_entries = 1,
};

static inline __attribute__((always_inline)) u8 ip_payload_off(struct iphdr *ip)
{
	u8 ip_off;

	ip_off = ip->ihl;
	ip_off &= 0x0f;
	ip_off *= 4;
	return ip_off;
}

static inline __attribute__((always_inline)) struct udp_info *
udp4_info_lazy(struct __sk_buff *skb, struct iphdr *ip, int *payload_off,
	       int *payload_sz)
{
	struct udp_info *info;
	struct udphdr udp;
	int err, zero = 0;
	__u8 udp_off;

	info = map_lookup_elem(&udp_info_heap, &zero);
	if (!info)
		return 0;

	udp_off = ip_payload_off(ip);

	err = skb_load_bytes(skb, udp_off, &udp, sizeof(struct udphdr));
	if (err)
		return 0;

	info->saddr = ip->saddr;
	info->daddr = ip->daddr;
	info->sport = udp.source;
	info->dport = udp.dest;
	info->padding = 0;
	info->cookie = 0;

	if (!info->cookie && skb)
		write_cookie(info, (u64)skb->sk);

	*payload_off = udp_off + sizeof(struct udphdr);
	*payload_sz = bpf_ntohs(udp.len) - sizeof(struct udphdr);
	return info;
}

static inline __attribute__((always_inline)) struct udp_info *
udp4_info_lazy_kp(struct sock *sk, struct iphdr *ip, void *data,
		  int *payload_off, int *payload_sz)
{
	struct udp_info *info;
	struct udphdr udp;
	int zero = 0;
	__u8 udp_off;

	info = map_lookup_elem(&udp_info_heap, &zero);
	if (!info)
		return 0;

	udp_off = ip_payload_off(ip);

	if (probe_read(&udp, sizeof(struct udphdr), data + udp_off) < 0)
		return 0;

	info->saddr = ip->saddr;
	info->daddr = ip->daddr;
	info->sport = udp.source;
	info->dport = udp.dest;
	info->padding = 0;

	write_cookie(info, (u64)sk);

	*payload_off = udp_off + sizeof(struct udphdr);
	*payload_sz = bpf_ntohs(udp.len) - sizeof(struct udphdr);
	return info;
}

static inline __attribute__((always_inline)) struct udp_info *
udp4_info(struct __sk_buff *skb, struct iphdr *ip, void *data, void *data_end,
	  int *payload_off, int *payload_sz, bool cookie)
{
	struct udp_info *info;
	struct udphdr *udp;
	int zero = 0;
	__u8 udp_off;

	info = map_lookup_elem(&udp_info_heap, &zero);
	if (!info)
		return 0;

	udp_off = ip_payload_off(ip);

	udp = (struct udphdr *)(data + udp_off);
	if (data + udp_off + sizeof(*udp) > data_end)
		return 0;

	info->saddr = ip->saddr;
	info->daddr = ip->daddr;
	info->sport = udp->source;
	info->dport = udp->dest;
	info->padding = 0;
	if (cookie)
		info->cookie = get_socket_cookie(skb);
	else
		info->cookie = 0;

	*payload_off = udp_off + sizeof(struct udphdr);
	*payload_sz = bpf_ntohs(udp->len) - sizeof(struct udphdr);
	return info;
}

static inline __attribute__((always_inline)) void
swap_info(struct udp_info *info)
{
	u32 addr = info->saddr;
	u16 port = info->sport;

	info->saddr = info->daddr;
	info->sport = info->dport;
	info->daddr = addr;
	info->dport = port;
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
 * reused. We can handle this by removing the entry on socket close()
 * and on process exit.
 * The process is then populated from the skb_consume_udp path where
 * we are in user context and can get the process info through normal
 * event_find_curr() hooks. We can't do that here because the current
 * pointer is set to kernel context at IP stack. This is not ideal
 * because it can mean if no process calls recv() on the data it may
 * never be accounted for. It will however, be in the udp_map and
 * user space can decide how to handle these cases. In the worse
 * case its expected user space can use the tuple key and timestamp
 * plus socket events to track back the process in a time series
 * database.
 */
static inline __attribute__((always_inline)) struct udp_info_value *
__udp4_send(struct __sk_buff *skb, struct udp_info *info, int payload_off,
	    int payload_sz, bool send)
{
	struct udp_info_value *value;
	struct execve_map_value *process;
	int zero = 0;

	value = map_lookup_elem(&udp_map, &info->cookie);
	process = map_lookup_elem(&socket_cookie_to_proc_map, &info->cookie);

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
		value->saddr = info->saddr;
		value->daddr = info->daddr;
		value->sport = info->sport;
		value->dport = info->dport;
		value->padding = 0;

		/* If process was found, fill in the PID */
		if (process) {
			value->pid = process->key.pid;
			value->pid_ktime = process->key.ktime;
		} else {
			value->pid = 0;
		}
		if (value->pid)
			emit_udp_connect_event(skb, value);
		map_update_elem(&udp_map, &info->cookie, value, 0);
	} else if (process && value->pid != process->key.pid) {
		/* PID doesn't match, so this must be a new socket */
		if (send)
			udp_info_tx_reset(value, payload_sz);
		else
			udp_info_rx_reset(value, payload_sz);

		value->saddr = info->saddr;
		value->daddr = info->daddr;
		value->sport = info->sport;
		value->dport = info->dport;
		value->padding = 0;
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

/* Lazy versions of udp4 send have a deficiency that make them
 * sub-optimal. The payload copy to user land is not supported
 * this is to support loading on older kernels without the necessary
 * bpf helpers.
 */
static inline __attribute__((always_inline)) int
udp4_send_lazy(struct __sk_buff *skb, struct iphdr *ip, bool send)
{
	int payload_off, payload_sz;
	struct udp_info *info;

	info = udp4_info_lazy(skb, ip, &payload_off, &payload_sz);
	if (!info)
		return 1;

	if (!send) {
		swap_info(info);
	}
	info->sport = bpf_ntohs(info->sport);
	__udp4_send(skb, info, payload_off, payload_sz, send);
	return 1;
}

static inline __attribute__((always_inline)) int
udp4_send_lazy_kp(void *ctx, struct sock *sk, struct iphdr *ip, void *data,
		  bool send)
{
	int payload_off, payload_sz;
	struct udp_info *info;

	info = udp4_info_lazy_kp(sk, ip, data, &payload_off, &payload_sz);
	if (!info)
		return 1;

	if (!send) {
		swap_info(info);
	}
	info->sport = bpf_ntohs(info->sport);
	__udp4_send(ctx, info, payload_off, payload_sz, send);
	return 1;
}

static inline __attribute__((always_inline)) int
dns_port_match(u16 *ports, u16 port1, u16 port2)
{
	if (ports[0] == port1 || ports[0] == port2 || ports[1] == port1 ||
	    ports[1] == port2 || ports[2] == port1 || ports[2] == port2 ||
	    ports[3] == port1 || ports[3] == port2) {
		return 1;
	}
	return 0;
}

static inline __attribute__((always_inline)) int
udp4_send(struct __sk_buff *skb, struct iphdr *ip, void *data, void *data_end,
	  bool send, bool cookie)
{
	int zero, payload_off, payload_sz;
	struct udp_info_value *value;
	struct udp_info *info;
	struct udp_sensor_config *config;

	info = udp4_info(skb, ip, data, data_end, &payload_off, &payload_sz,
			 cookie);
	if (!info)
		return 1;

	if (!send) {
		swap_info(info);
	}
	info->sport = bpf_ntohs(info->sport);

	value = __udp4_send(skb, info, payload_off, payload_sz, send);
	if (!value)
		return 1;

	zero = 0;
	config = map_lookup_elem(&udp_config_map, &zero);
	if (!config)
		return 1;

	if (config->dnsPorts[0] != 0 &&
	    dns_port_match(config->dnsPorts, info->sport,
			   bpf_ntohs(info->dport))) {
		/* We subtract 1 from payload_sz because we need to +1 it
		 * later to sat verifier constraint that skb_load_bytes
		 * must be nonzero.
		 */
		emit_udp_payload_event(skb, value, payload_off, payload_sz - 1);
	}
	return 1;
}

static inline __attribute__((always_inline)) void
udp_burst(struct __sk_buff *skb, struct iphdr *ip, u64 send, bool lazy)
{
	struct udp_sensor_config *config;
	struct process_network_burst_config c;
	struct udp_info *info;
	struct execve_map_value *process;
	u8 udp_off;
	struct udphdr udp;
	int vol;

	int zero = 0;

	config = map_lookup_elem(&udp_config_map, &zero);
	if (!config || !config->watermark_enable)
		return;

	/* Using udp_info_key as heap to save making another map just
	 * to store the cookie, as v5.4 doesn't like a direct read from
	 * the stack.
	 */
	info = map_lookup_elem(&udp_info_heap, &zero);
	if (!info)
		return;

	c.avg_window_size_ms = config->watermark_avg_window_size_ms;
	c.window_size = config->watermark_window_size;
	c.trigger_mult = config->watermark_trigger_percent;
	c.ctx = skb;

	if (lazy) {
		write_cookie(info, (u64)skb->sk);
	} else {
		info->cookie = get_socket_cookie(skb);
	}

	process = map_lookup_elem(&socket_cookie_to_proc_map, &info->cookie);
	/* If we don't have a process then we can't assign the burst information
	 * to it, and there is little else we can do.
	 */
	if (!process)
		return;

	udp_off = ip_payload_off(ip);
	int err = skb_load_bytes(skb, udp_off, &udp, sizeof(struct udphdr));
	if (err)
		return;
	vol = bpf_ntohs(udp.len) - sizeof(struct udphdr);

	process_network_burst(process, IPPROTO_UDP, send, vol, &c);
}

static inline __attribute__((always_inline)) void
udp_burst_kp(void *ctx, struct sock *sk, struct iphdr *ip, void *data, u64 send)
{
	struct udp_sensor_config *config;
	struct process_network_burst_config c;
	struct udp_info *info;
	struct execve_map_value *process;
	u8 udp_off;
	struct udphdr udp;
	int vol;
	u64 cookie = (u64)sk;

	int zero = 0;

	config = map_lookup_elem(&udp_config_map, &zero);
	if (!config || !config->watermark_enable)
		return;

	/* Using udp_info_key as heap to save making another map just
	 * to store the cookie, as v5.4 doesn't like a direct read from
	 * the stack.
	 */
	info = map_lookup_elem(&udp_info_heap, &zero);
	if (!info)
		return;

	c.avg_window_size_ms = config->watermark_avg_window_size_ms;
	c.window_size = config->watermark_window_size;
	c.trigger_mult = config->watermark_trigger_percent;
	c.ctx = ctx;

	process = map_lookup_elem(&socket_cookie_to_proc_map, &cookie);
	/* If we don't have a process then we can't assign the burst information
	 * to it, and there is little else we can do.
	 */
	if (!process)
		return;

	udp_off = ip_payload_off(ip);

	if (probe_read(&udp, sizeof(struct udphdr), data + udp_off) < 0)
		return;

	vol = bpf_ntohs(udp.len) - sizeof(struct udphdr);

	process_network_burst(process, IPPROTO_UDP, send, vol, &c);
}

static inline __attribute__((always_inline)) void
inet_handler_lazy(struct __sk_buff *skb, int send)
{
	struct iphdr ip;
	u8 v4_prot;
	int err;

	err = skb_load_bytes(skb, 0, &ip, sizeof(struct iphdr));
	if (err < 0) {
		return;
	}
	v4_prot = ip.protocol;
	if (v4_prot == IPPROTO_UDP) {
		udp4_send_lazy(skb, &ip, send);
		udp_burst(skb, &ip, send, true);
	}
	return;
}

static inline __attribute__((always_inline)) void
inet_handler_lazy_kp(void *ctx, struct sock *sk, struct sk_buff *skb, int send)
{
	void *data;
	void *skb_head;
	struct iphdr ip;
	u8 v4_prot;
	u16 network_header;

	probe_read(&network_header, sizeof(u16), _(&skb->network_header));
	probe_read(&skb_head, sizeof(void *), _(&skb->head));

	data = skb_head + network_header;

	if (probe_read(&ip, sizeof(struct iphdr), data) < 0) {
		return;
	}

	v4_prot = ip.protocol;

	if (v4_prot == IPPROTO_TCP) { // TCP
		return;
	} else if (v4_prot == IPPROTO_UDP) { // UDP
		udp4_send_lazy_kp(ctx, sk, &ip, data, send);
		udp_burst_kp(ctx, sk, &ip, data, send);
	}
	return;
}

static inline __attribute__((always_inline)) void
inet_handler(struct __sk_buff *skb, int send, int cookie)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (long *)(long)skb->data;
	struct iphdr *ip;
	u8 v4_prot;

	if (data + sizeof(struct iphdr) > data_end)
		return;
	ip = (struct iphdr *)data;
	v4_prot = ip->protocol;

	if (v4_prot == IPPROTO_TCP) { // TCP
		return;
	} else if (v4_prot == IPPROTO_UDP) { // UDP
		udp4_send(skb, ip, data, data_end, send, cookie);
		udp_burst(skb, ip, send, false);
	}
	return;
}

#endif //__BPF_INET_H_
