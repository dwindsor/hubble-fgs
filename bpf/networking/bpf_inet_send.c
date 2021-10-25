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
int udp4_send(struct __sk_buff *skb, struct iphdr *ip, void *data, void *data_end)
{
	struct udp_info_value *value;
	struct udp_info_key *key;
	struct udphdr *udp;
	int zero = 0;
	__u8 udp_off;

	key = map_lookup_elem(&udp_key_heap, &zero);
	if (!key)
		return 1;

	udp_off = ip->ihl;
	udp_off &= 0x0f;
	udp_off *= 4;

	udp = (struct udphdr *)(data + udp_off);
	if (data + udp_off + sizeof(*udp) > data_end)
		return 1;

	key->saddr = ip->saddr;
	key->daddr = ip->daddr;
	key->sport = udp->source;
	key->dport = udp->dest;
	key->cookie = get_socket_cookie(skb);

	value = map_lookup_elem(&udp_map, key);
	if (!value) {
		struct execve_map_value *process;

		value = map_lookup_elem(&udp_value_heap, &zero);
		if (!value)
			return 1;

		process = map_lookup_elem(&socket_cookie_to_proc_map,
					  &key->cookie);
		if (process) {
			value->pid = process->key.pid;
			value->ktime = process->key.ktime;
		}
		map_update_elem(&udp_map, key, value, 0);
		emit_udp_connect_event(skb, key, value);
	}
	return 1;
}

__attribute__((section(("cgroup_skb/egress")), used))
int inet_send(struct __sk_buff *skb)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (long *)(long)skb->data;
	struct iphdr *ip;
	u8 v4_prot;

	if (data + sizeof(struct iphdr) > data_end)
		return 1;
	ip = (struct iphdr *)data;
	v4_prot = ip->protocol;

	if (v4_prot == IPPROTO_TCP) { // TCP
		return 1;
	} else if (v4_prot == IPPROTO_UDP) { // UDP
		return udp4_send(skb, ip, data, data_end);
	}
	return SK_PASS;
}
