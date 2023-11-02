#ifndef __ICMP_COOKIE_H_
#define __ICMP_COOKIE_H_

#include "vmlinux.h"
#include "../lib/iso_msg_types.h"
#include "../lib/networkmsg.h"
#include "../lib/tlsmsg.h"
#include "../lib/config.h"
#include "../lib/address_family.h"
#include "../cookie.h"
#include "bpf_tracing.h"

/* We store the mapping from socket tuples to socket cookies so that ICMP datagrams (other than
 * ping), and any other datagrams as required, can be mapped to the socket they reference. ICMP
 * datagrams are transmitted over kernel icmp sockets, but reference TCP and UDP sockets (e.g.
 * a "destination unreachable" icmp message relates to a socket that failed in transmission).
 * The kernel (see raw_icmp_error() in net/ipv4/raw.c) maps them to sockets based on a number
 * of parameters shared between the skb itself and the socket it references. We store these
 * mappings in a hash for cheap look up.
*/
struct socket_tuple_key {
	struct net *net;
	__u64 saddr[2];
	__u64 daddr[2];
	__s32 bound_dev_if;
	__u16 family;
	__u16 protocol;
	__u16 sport;
	__u16 pad[3];
};

/* Socket tuples could have a zeroed saddr, daddr, and/or bound_dev_if. This means on lookup,
 * we need to check all combinations where these could be zero or could be values from the skb.
 * A naive approach would require up to 12 look ups. Instead, we create a hint that tells us
 * which values could be zero for entries that otherwise match. We then only need to try with
 * zero values for the parameters specified, which should reduce the number of look ups.
 * We ref count entries so we know when to delete them.
 */
struct socket_tuple_hint_key {
	struct net *net;
	__u16 family;
	__u16 protocol;
	__u16 sport;
	__u16 pad;
};

struct socket_tuple_hint_value {
	__u32 saddr_zero;
	__u32 daddr_zero;
	__u32 bound_dev_if_zero;
	__u32 refcnt;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct socket_tuple_key);
	__type(value, u64);
	__uint(max_entries, 32768);
} tg_socket_tuple_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __s32);
	__type(value, __s64);
	__uint(max_entries, 1);
} tg_socket_tuple_map_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct socket_tuple_hint_key);
	__type(value, struct socket_tuple_hint_value);
	__uint(max_entries, 32768);
} tg_socket_tuple_hint_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct socket_tuple_key);
	__uint(max_entries, 1);
} tg_socket_tuple_heap SEC(".maps");

static inline __attribute__((always_inline)) bool
icmp_tracking_enabled()
{
	struct cfg_value *cfg;
	int zero = 0;

	cfg = (struct cfg_value *)map_lookup_elem(&tg_cfg_map, &zero);
	if (!cfg || !cfg->icmp_tracking_enabled)
		return false;
	return true;
}

static inline __attribute__((always_inline)) bool
icmp_net_match()
{
	struct cfg_value *cfg;
	int zero = 0;

	cfg = (struct cfg_value *)map_lookup_elem(&tg_cfg_map, &zero);
	if (!cfg || !cfg->icmp_net_match)
		return false;
	return true;
}

static inline __attribute__((always_inline)) struct socket_tuple_key *
make_tuple_key_from_sk(struct sock *sk)
{
	struct socket_tuple_key *key;
	int zero = 0;

	key = (struct socket_tuple_key *)map_lookup_elem(&tg_socket_tuple_heap, &zero);
	if (!key)
		return 0;

	if (icmp_net_match() && bpf_core_field_size(sk->__sk_common.skc_net) > 0) {
		probe_read_kernel(&key->net, sizeof(key->net), _(&(sk->__sk_common.skc_net)));
	} else {
		key->net = 0;
	}
	probe_read_kernel(&key->family, sizeof(key->family), _(&(sk->__sk_common.skc_family)));
	if (key->family == AF_INET6) {
		probe_read_kernel(key->saddr, sizeof(key->saddr), _(&(sk->__sk_common.skc_v6_rcv_saddr)));
		probe_read_kernel(key->daddr, sizeof(key->daddr), _(&(sk->__sk_common.skc_v6_daddr)));
	} else {
		key->saddr[0] = 0;
		probe_read_kernel(&key->saddr[0], sizeof(__u32), _(&(sk->__sk_common.skc_rcv_saddr)));
		key->saddr[1] = 0;
		key->daddr[0] = 0;
		probe_read_kernel(&key->daddr[0], sizeof(__u32), _(&(sk->__sk_common.skc_daddr)));
		key->daddr[0] = 0;
	}
	probe_read_kernel(&key->bound_dev_if, sizeof(key->bound_dev_if), _(&(sk->__sk_common.skc_bound_dev_if)));
	probe_read_kernel(&key->protocol, sizeof(key->protocol), _(&(sk->sk_protocol)));
	if (bpf_core_field_size(sk->sk_protocol) == sizeof(u32)) {
		key->protocol >>= 8;
	}
	probe_read_kernel(&key->sport, sizeof(key->sport), _(&(sk->__sk_common.skc_num)));
	return key;
}

struct ihlver {
	__u8 ihl : 4,
		version : 4;
};

static inline __attribute__((always_inline)) struct socket_tuple_key *
make_tuple_key_from_skb(struct sk_buff *skb, struct msg_icmp_event *val, void *reported_datagram)
{
	struct socket_tuple_key *key;
	struct net_device *skb_dev;
	struct udphdr *udp;
	struct tcphdr *tcp;
	struct iphdr *ip4;
	struct ihlver iv;
	int zero = 0;
	u8 protocol;

	key = map_lookup_elem(&tg_socket_tuple_heap, &zero);
	if (!key)
		return 0;

	if (icmp_net_match() && bpf_core_field_size(skb->dev->nd_net) > 0) {
		probe_read_kernel(&skb_dev, sizeof(skb_dev), _(&(skb->dev)));
		probe_read_kernel(&key->net, sizeof(key->net), _(&(skb_dev->nd_net)));
	} else {
		key->net = 0;
	}
	if (val->tuple.ipv6)
		key->family = AF_INET6;
	else
		key->family = AF_INET;

	key->saddr[0] = val->tuple.saddr[0];
	key->saddr[1] = val->tuple.saddr[1];
	key->daddr[0] = val->tuple.daddr[0];
	key->daddr[1] = val->tuple.daddr[1];
	// bound_dev_if will be filled in during look up.
	key->bound_dev_if = 0;

	// Extract protocol and sport from embedded datagram headers.
	if (!val->tuple.ipv6) {
		ip4 = (struct iphdr *)reported_datagram;
		// Read the IHL/Version byte from the start of the IPv4 header.
		probe_read_kernel(&iv, sizeof(iv), ip4);
		probe_read_kernel(&protocol, sizeof(protocol), _(&(ip4->protocol)));
		key->protocol = protocol;
		switch (protocol) {
		case IPPROTO_UDP:
			udp = (struct udphdr *)(reported_datagram + (iv.ihl * sizeof(u32)));
			probe_read_kernel(&key->sport, sizeof(key->sport), _(&(udp->source)));
			key->sport = bpf_ntohs(key->sport);
			break;
		case IPPROTO_TCP:
			tcp = (struct tcphdr *)(reported_datagram + (iv.ihl * sizeof(u32)));
			probe_read_kernel(&key->sport, sizeof(key->sport), _(&(tcp->source)));
			key->sport = bpf_ntohs(key->sport);
			break;
		default:
			return 0;
		}
	} else {
		return 0;
	}
	return key;
}

static inline __attribute__((always_inline)) struct socket_tuple_key *
make_tuple_key_from_cgroup_skb(struct __sk_buff *skb, u16 protocol)
{
	struct socket_tuple_key *key;
	int zero = 0;

	key = map_lookup_elem(&tg_socket_tuple_heap, &zero);
	if (!key)
		return 0;

	key->net = 0;
	key->family = skb->family;
	if (key->family == AF_INET6) {
		key->saddr[0] = *(u64 *)skb->local_ip6;
		key->saddr[1] = *(u64 *)&skb->local_ip6[2];
		key->daddr[0] = *(u64 *)skb->remote_ip6;
		key->daddr[1] = *(u64 *)&skb->remote_ip6[2];
	} else {
		key->saddr[0] = skb->local_ip4;
		key->saddr[0] = 0;
		key->daddr[0] = skb->remote_ip4;
		key->daddr[0] = 0;
	}

	key->bound_dev_if = skb->ifindex;
	key->protocol = protocol;
	key->sport = skb->local_port;

	return key;
}

static inline __attribute__((always_inline)) void
set_tuple_hint(struct socket_tuple_key *key)
{
	struct socket_tuple_hint_value new_val = {};
	struct socket_tuple_hint_key hkey = {};
	struct socket_tuple_hint_value *val;

	hkey.family = key->family;
	hkey.net = key->net;
	hkey.protocol = key->protocol;
	hkey.sport = key->sport;

	val = map_lookup_elem(&tg_socket_tuple_hint_map, &hkey);
	if (!val)
		val = &new_val;

	if (!key->saddr[0] && !key->saddr[1])
		val->saddr_zero++;
	if (!key->daddr[0] && !key->daddr[1])
		val->daddr_zero++;
	if (!key->bound_dev_if)
		val->bound_dev_if_zero++;
	val->refcnt++;

	if (val == &new_val)
		map_update_elem(&tg_socket_tuple_hint_map, &hkey, val, 0);
}

static inline __attribute__((always_inline)) void
delete_tuple_hint(struct socket_tuple_key *key)
{
	struct socket_tuple_hint_key hkey = {};
	struct socket_tuple_hint_value *val;

	hkey.family = key->family;
	hkey.net = key->net;
	hkey.protocol = key->protocol;
	hkey.sport = key->sport;

	val = map_lookup_elem(&tg_socket_tuple_hint_map, &hkey);
	if (!val)
		return;

	if (!key->saddr[0] && !key->saddr[1] && val->saddr_zero)
		val->saddr_zero--;
	if (!key->daddr[0] && !key->daddr[1] && val->daddr_zero)
		val->daddr_zero--;
	if (!key->bound_dev_if && val->bound_dev_if_zero)
		val->bound_dev_if_zero--;
	if (val->refcnt)
		val->refcnt--;
	if (!val->refcnt)
		map_delete_elem(&tg_socket_tuple_hint_map, &hkey);
}

static inline __attribute__((always_inline)) struct socket_tuple_hint_value *
get_tuple_hint(struct socket_tuple_key *key)
{
	struct socket_tuple_hint_key hkey = {};

	hkey.family = key->family;
	hkey.net = key->net;
	hkey.protocol = key->protocol;
	hkey.sport = key->sport;

	return map_lookup_elem(&tg_socket_tuple_hint_map, &hkey);
}

static inline __attribute__((always_inline)) void
__add_socket_tuple_map(u64 *cookie, struct socket_tuple_key *key)
{
	int zero = 0;
	__s64 *cntr;
	__u64 *val;
	int err;

	val = map_lookup_elem(&tg_socket_tuple_map, key);
	if (val && *val == *cookie)
		return;

	if (val)
		delete_tuple_hint(key);

	err = map_update_elem(&tg_socket_tuple_map, key, cookie, 0);
	if (!err) {
		if ((cntr = (__s64 *)map_lookup_elem(&tg_socket_tuple_map_stats, &zero)))
			*cntr = *cntr + 1;
		set_tuple_hint(key);
	}
}

static inline __attribute__((always_inline)) void
add_socket_tuple_map(u64 *cookie)
{
	struct sock *sk = (struct sock *)*cookie;
	struct socket_tuple_key *key;

	if (!icmp_tracking_enabled())
		return;

	key = make_tuple_key_from_sk(sk);
	if (!key)
		return;

	__add_socket_tuple_map(cookie, key);
}

static inline __attribute__((always_inline)) void
add_socket_tuple_map_from_skb(u64 *cookie, struct __sk_buff *skb, u16 protocol)
{
	struct socket_tuple_key *key;

	if (!icmp_tracking_enabled())
		return;

	key = make_tuple_key_from_cgroup_skb(skb, protocol);
	if (!key)
		return;

	__add_socket_tuple_map(cookie, key);
}

static inline __attribute__((always_inline)) void
del_socket_tuple_map(u64 *cookie)
{
	struct sock *sk = (struct sock *)*cookie;
	struct socket_tuple_key *key;
	int zero = 0;
	__s64 *cntr;
	int err;

	if (!icmp_tracking_enabled())
		return;

	key = make_tuple_key_from_sk(sk);
	if (!key)
		return;
	err = map_delete_elem(&tg_socket_tuple_map, key);
	if (!err) {
		if ((cntr = (__s64 *)map_lookup_elem(&tg_socket_tuple_map_stats, &zero)))
			*cntr = *cntr - 1;
		delete_tuple_hint(key);
	}
}

struct netns_ipv4___with_l3mdev {
	__u8 sysctl_raw_l3mdev_accept;
};

static inline __attribute__((always_inline)) __u8
get_l3mdev_accept(struct net *net)
{
	struct netns_ipv4___with_l3mdev *ipv4 = (struct netns_ipv4___with_l3mdev *)&net->ipv4;
	__u8 val;

	if (bpf_core_field_exists(ipv4->sysctl_raw_l3mdev_accept)) {
		probe_read_kernel(&val, sizeof(val), _(&(ipv4->sysctl_raw_l3mdev_accept)));
		return val;
	}
	return 1;
}

static inline __attribute__((always_inline)) __u64 *
lookup_socket_tuple_map(struct socket_tuple_key *key, int dif, int sdif)
{
	uint max_saddr = 1, max_daddr = 1, max_if = 2;
	struct socket_tuple_hint_value *val;
	struct socket_tuple_key lookup_key = {};
	uint saddr_cnt, daddr_cnt, if_cnt;
	__u64 *cookie;

	val = get_tuple_hint(key);
	if (!val)
		return 0;

	lookup_key.net = key->net;
	lookup_key.family = key->family;
	lookup_key.protocol = key->protocol;
	lookup_key.sport = key->sport;

	if (val->saddr_zero)
		max_saddr = 2;
	if (val->daddr_zero)
		max_daddr = 2;
	if (val->bound_dev_if_zero)
		max_if = 3;

	for (saddr_cnt = 0; saddr_cnt < max_saddr; saddr_cnt++) {
		for (daddr_cnt = 0; daddr_cnt < max_daddr; daddr_cnt++) {
			for (if_cnt = 0; if_cnt < max_if; if_cnt++) {
				switch (saddr_cnt) {
				case 0:
					lookup_key.saddr[0] = key->saddr[0];
					lookup_key.saddr[1] = key->saddr[1];
					break;
				case 1:
					lookup_key.saddr[0] = 0;
					lookup_key.saddr[1] = 0;
					break;
				}
				switch (daddr_cnt) {
				case 0:
					lookup_key.daddr[0] = key->daddr[0];
					lookup_key.daddr[1] = key->daddr[1];
					break;
				case 1:
					lookup_key.daddr[0] = 0;
					lookup_key.daddr[1] = 0;
					break;
				}
				switch (if_cnt) {
				case 0:
					lookup_key.bound_dev_if = dif;
					break;
				case 1:
					lookup_key.bound_dev_if = sdif;
					break;
				case 2:
					lookup_key.bound_dev_if = 0;
					break;
				}
				cookie = map_lookup_elem(&tg_socket_tuple_map, &lookup_key);
				if (!cookie)
					continue;
				if (lookup_key.bound_dev_if != 0 || !sdif || get_l3mdev_accept(lookup_key.net))
					return cookie;
			}
		}
	}
	return 0;
}

#endif
