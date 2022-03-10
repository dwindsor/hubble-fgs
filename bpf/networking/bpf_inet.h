#ifndef __BPF_INET_H_
#define __BPF_INET_H_

#ifndef bpf_map_def
struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};
#endif

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

static inline __attribute__((always_inline))
u8 ip_payload_off(struct iphdr *ip)
{
	u8 ip_off;

	ip_off = ip->ihl;
	ip_off &= 0x0f;
	ip_off *= 4;
	return ip_off;
}

static inline __attribute__((always_inline))
struct udp_info_key *udp4_key_lazy(struct __sk_buff *skb,
			      struct iphdr *ip,
			      int *payload_off, int *payload_sz)
{
	struct udp_info_key *key;
	struct udphdr udp;
	int err, zero = 0;
	__u8 udp_off;

	key = map_lookup_elem(&udp_key_heap, &zero);
	if (!key)
		return 0;

	udp_off = ip_payload_off(ip);

	err = skb_load_bytes(skb, udp_off, &udp, sizeof(struct udphdr));
	if (err)
		return 0;

	key->saddr = ip->saddr;
	key->daddr = ip->daddr;
	key->sport = udp.source;
	key->dport = udp.dest;
	key->padding = 0;
	key->cookie = 0;

	*payload_off = udp_off + sizeof(struct udphdr);
	*payload_sz = bpf_ntohs(udp.len) - sizeof(struct udphdr);
	return key;
}

static inline __attribute__((always_inline))
struct udp_info_key *udp4_key(struct __sk_buff *skb, struct iphdr *ip, void *data, void *data_end, int *payload_off, int *payload_sz, bool cookie)
{
	struct udp_info_key *key;
	struct udphdr *udp;
	int zero = 0;
	__u8 udp_off;

	key = map_lookup_elem(&udp_key_heap, &zero);
	if (!key)
		return 0;

	udp_off = ip_payload_off(ip);

	udp = (struct udphdr *)(data + udp_off);
	if (data + udp_off + sizeof(*udp) > data_end)
		return 0;

	key->saddr = ip->saddr;
	key->daddr = ip->daddr;
	key->sport = udp->source;
	key->dport = udp->dest;
	key->padding = 0;
	if (cookie)
		key->cookie = get_socket_cookie(skb);
	else
		key->cookie = 0;

	*payload_off = udp_off + sizeof(struct udphdr);
	*payload_sz = bpf_ntohs(udp->len) - sizeof(struct udphdr);
	return key;
}

static inline __attribute__((always_inline))
void swap_key(struct udp_info_key *key)
{
	u32 addr = key->saddr;
	u16 port = key->sport;

	key->saddr = key->daddr;
	key->sport = key->dport;
	key->daddr = addr;
	key->dport = port;
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
 * To accomodate older kernels that do not have cookie set we leave
 * pid and pid_ktime empty on receive case when no proces is found.
 * These values are then populated from the skb_consume_udp path where
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
static inline __attribute__((always_inline))
struct udp_info_value *__udp4_send(struct __sk_buff *skb,
				   struct udp_info_key *key,
				   int payload_off, int payload_sz, bool send)
{
	struct udp_info_value *value;
	int zero = 0;

	value = map_lookup_elem(&udp_map, key);
	if (!value) {
		struct execve_map_value *process;

		value = map_lookup_elem(&udp_value_heap, &zero);
		if (!value)
			return 0;

		if (send)
			udp_info_tx_reset(value, payload_sz);
		else
			udp_info_rx_reset(value, payload_sz);

		process = map_lookup_elem(&socket_cookie_to_proc_map,
					  &key->cookie);
		if (process) {
			value->pid = process->key.pid;
			value->pid_ktime = process->key.ktime;
		} else {
			value->pid = 0;
			value->pid_ktime = 0;
		}
		map_update_elem(&udp_map, key, value, 0);
	} else {
		if (send)
			update_tx_value(value, payload_sz);
		else
			update_rx_value(value, payload_sz);
	}
	return value;
}

/* Lazy versions of udp4 send have two deficiencies that make them
 * sub-optimal. First keys do not include cookie info this means we
 * could in-theory collide across network namespaces, e.g. two sockets
 * in different network namespaces with the same 5-tuple will aggregate
 * their statistics -- this feels unlikely. The other one is payload
 * copy to user land is not supported this is to support loading on
 * older kernels without the necessary bpf helpers.
 */
static inline __attribute__((always_inline))
int udp4_send_lazy(struct __sk_buff *skb, struct iphdr *ip, bool send)
{
	int payload_off, payload_sz;
	struct udp_info_key *key;

	key = udp4_key_lazy(skb, ip, &payload_off, &payload_sz);
	if (!key)
		return 1;

	if (!send) {
		swap_key(key);
		key->sport = bpf_ntohs(key->sport);
	} else {
		key->sport = bpf_ntohs(key->sport);
	}
	__udp4_send(skb, key, payload_off, payload_sz, send);
	return 1;
}

static inline __attribute__((always_inline))
int dns_port_match(u16 *ports, u16 port1, u16 port2)
{
	if (ports[0] == port1 || ports[0] == port2 ||
		ports[1] == port1 || ports[1] == port2 ||
		ports[2] == port1 || ports[2] == port2 ||
		ports[3] == port1 || ports[3] == port2) {
		return 1;
	}
	return 0;
}

static inline __attribute__((always_inline))
int udp4_send(struct __sk_buff *skb, struct iphdr *ip, void *data, void *data_end, bool send, bool cookie)
{
	int zero, payload_off, payload_sz;
	struct udp_info_value *info;
	struct udp_info_key *key;
	struct udp_sensor_config *config;

	key = udp4_key(skb, ip, data, data_end, &payload_off, &payload_sz, cookie);
	if (!key)
		return 1;

	if (!send) {
		swap_key(key);
		key->sport = bpf_ntohs(key->sport);
	} else {
		key->sport = bpf_ntohs(key->sport);
	}

	info = __udp4_send(skb, key, payload_off, payload_sz, send);
	if (!info)
		return 1;

	zero = 0;
	config = map_lookup_elem(&udp_config_map, &zero);
	if (!config)
		return 1;

	if (config->dnsPorts[0] != 0 && dns_port_match(config->dnsPorts, key->sport, bpf_ntohs(key->dport))) {
		/* We subtract 1 from payload_sz because we need to +1 it
		 * later to sat verifier constraint that skb_load_bytes
		 * must be nonzero.
		 */
		emit_udp_payload_event(skb, key, info, payload_off, payload_sz - 1);
	}
	return 1;
}

static inline __attribute__((always_inline))
void udp_burst(struct __sk_buff *skb, struct iphdr *ip, void *data, void *data_end, u64 send)
{
	struct udp_sensor_config *config;
	struct process_network_burst_config c;
	u64 cookie;
	struct execve_map_value *process;
	u8 udp_off;
	struct udphdr *udp;
	int vol;

	int zero = 0;

	config = map_lookup_elem(&udp_config_map, &zero);
	if (!config || !config->watermark_enable)
		return;

	c.avg_window_size_ms = config->watermark_avg_window_size_ms;
	c.window_size = config->watermark_window_size;
	c.trigger_mult = config->watermark_trigger_percent;
	c.ctx = skb;

	cookie = get_socket_cookie(skb);
	process = map_lookup_elem(&socket_cookie_to_proc_map, &cookie);
	if (!process)
		return;

	udp_off = ip_payload_off(ip);
	udp = (struct udphdr *)(data + udp_off);
	if (data + udp_off + sizeof(*udp) > data_end)
		return;
	vol = bpf_ntohs(udp->len) - sizeof(struct udphdr);

	process_network_burst(process, IPPROTO_UDP, send, vol, &c);
}

static inline __attribute__((always_inline))
void inet_handler_lazy(struct __sk_buff *skb, int send)
{
	struct iphdr ip;
	u8 v4_prot;
	int err;

	err = skb_load_bytes(skb, 0, &ip, sizeof(struct iphdr));
	if (err < 0) {
		return;
	}
	v4_prot = ip.protocol;
	if (v4_prot == IPPROTO_UDP)
		udp4_send_lazy(skb, &ip, send);
	return;
}

static inline __attribute__((always_inline))
void inet_handler(struct __sk_buff *skb, int send, int cookie)
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
		udp_burst(skb, ip, data, data_end, send);
	}
	return;
}

#endif //__BPF_INET_H_
