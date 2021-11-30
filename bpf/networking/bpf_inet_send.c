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

#define SOCK_CTX

struct bpf_map_def __attribute__((section("maps"), used)) udp_filter_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = 128,
	.max_entries = 1,
};

#include "api.h"
#include "hubble_msg.h"
#include "bpf_events.h"
#include "bpf_udp.h"
#include "cookie.h"

char _license[] __attribute__((section(("license")), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int  _version __attribute__((section(("version")), used)) = VMLINUX_KERNEL_VERSION;
#endif

static inline __attribute__((always_inline))
struct udp_info_key *udp4_key(struct __sk_buff *skb, struct iphdr *ip, void *data, void *data_end, int *payload_off, int *payload_sz)
{
	struct udp_info_key *key;
	struct udphdr *udp;
	int zero = 0;
	__u8 udp_off;

	key = map_lookup_elem(&udp_key_heap, &zero);
	if (!key)
		return 0;

	udp_off = ip->ihl;
	udp_off &= 0x0f;
	udp_off *= 4;

	udp = (struct udphdr *)(data + udp_off);
	if (data + udp_off + sizeof(*udp) > data_end)
		return 0;

	key->saddr = ip->saddr;
	key->daddr = ip->daddr;
	key->sport = udp->source;
	key->dport = udp->dest;
	key->cookie = get_socket_cookie(skb);
	key->padding = 0;

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

static inline __attribute__((always_inline))
int udp4_send(struct __sk_buff *skb, struct iphdr *ip, void *data, void *data_end, int send)
{
	int zero = 0, payload_off, payload_sz;
	u32 dnsport, *filter;

	struct udp_info_value *value;
	struct udp_info_key *key;

	key = udp4_key(skb, ip, data, data_end, &payload_off, &payload_sz);
	if (!key)
		return 1;

	if (!send) {
		swap_key(key);
		key->sport = bpf_ntohs(key->sport);
	} else {
		key->sport = bpf_ntohs(key->sport);
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
	 */
	value = map_lookup_elem(&udp_map, key);
	if (!value) {
		struct execve_map_value *process;

		value = map_lookup_elem(&udp_value_heap, &zero);
		if (!value)
			return 1;

		if (send)
			udp_info_tx_reset(value, skb->len);
		else
			udp_info_rx_reset(value, skb->len);

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
		emit_udp_connect_event(skb, key, value);
	} else {
		if (send)
			update_tx_value(value, skb->len);
		else
			update_rx_value(value, skb->len);
	}

	filter = map_lookup_elem(&udp_filter_map, &zero);
	if (!filter)
		return 1;

	dnsport = (u32)filter[0];
	if (key->sport == dnsport || bpf_ntohs(key->dport) == dnsport) {
		/* We subtract 1 from payload_sz because we need to +1 it
		 * later to sat verifier constraint that skb_load_bytes
		 * must be nonzero.
		 */
		emit_udp_payload_event(skb, key, value, payload_off, payload_sz - 1);
	}
	return 1;
}

static inline __attribute__((always_inline))
void inet_handler(struct __sk_buff *skb, int send)
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
		udp4_send(skb, ip, data, data_end, send);
	}
	return;
}

__attribute__((section(("cgroup_skb/egress")), used))
int inet_send(struct __sk_buff *skb)
{
	inet_handler(skb, 1);
	return SK_PASS;
}

__attribute__((section(("cgroup_skb/ingress")), used))
int inet_recv(struct __sk_buff *skb)
{
	inet_handler(skb, 0);
	return SK_PASS;
}
