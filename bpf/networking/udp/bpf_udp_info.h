#ifndef __BPF_UDP_INFO_H_
#define __BPF_UDP_INFO_H_

/* UDP Info maintains the statistics associated with a UDP "session".
 * Here we have the map and helper routines to setup keys and values.
 */

/* Maximum number of simultaniously existing UDP sockets that we track
 * statistics for.
 */
#define MAX_UDP_ENDPOINTS 32768

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct udp_info_key);
	__type(value, struct udp_info_value);
	__uint(max_entries, MAX_UDP_ENDPOINTS);
} tg_udp_map SEC(".maps");

struct udp_info_key {
	u64 cookie;
	u64 daddr[2];
	u16 dport;
	u8 ipv6;
	u8 padding1;
	u32 padding2;
}; // All fields aligned so no 'packed' attribute.

struct udp_info_value {
	u64 submitted_bytes;
	u64 tx_bytes;
	u64 consumed_bytes;
	u64 rx_bytes;
	u64 consumed_segs;
	u64 segs_in;
	u64 submitted_segs;
	u64 segs_out;
	u64 ktime;
	u64 pid_ktime;
	u32 pid;
	u32 sk_drops;
	u64 saddr[2];
	u64 daddr[2]; // retain (and complete) as useful for debugging
	u16 sport;
	u16 dport; // retain (and complete) as useful for debugging
	u32 skb_consume_misses;
	u64 buckets[8];
	u64 latency_sum;
	u8 ipv6;
	u8 padding[7];
	u64 create_time;
}; // All fields aligned so no 'packed' attribute.

struct udp_info {
	union {
		u32 ipv4;
		u64 ipv6[2];
	} saddr;
	union {
		u32 ipv4;
		u64 ipv6[2];
	} daddr;
	u16 sport;
	u16 dport;
	u8 ipv6;
	u8 padding[3];
}; // All fields aligned so no 'packed' attribute.

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct udp_info_value);
	__uint(max_entries, 1);
} tg_udp_value_heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct udp_info);
	__uint(max_entries, 1);
} tg_udp_info_heap SEC(".maps");

static inline __attribute__((always_inline)) void
udp_key(struct udp_info_key *key, struct iphdr *ip, bool ipv6, struct udphdr *udp, u64 send)
{
	if (send) {
		if (!ipv6) {
			key->daddr[0] = ip->daddr;
			key->daddr[1] = 0;
			key->ipv6 = false;
		} else {
			u64 *addr = (u64 *)&((struct ipv6hdr *)ip)->daddr;
			key->daddr[0] = addr[0];
			key->daddr[1] = addr[1];
			key->ipv6 = true;
		}
		// In the key, the port is always host order.
		key->dport = bpf_ntohs(udp->dest);
	} else {
		if (!ipv6) {
			key->daddr[0] = ip->saddr;
			key->daddr[1] = 0;
			key->ipv6 = false;
		} else {
			u64 *addr = (u64 *)&((struct ipv6hdr *)ip)->saddr;
			key->daddr[0] = addr[0];
			key->daddr[1] = addr[1];
			key->ipv6 = true;
		}
		// In the key, the port is always host order.
		key->dport = bpf_ntohs(udp->source);
	}
	key->padding1 = 0;
	key->padding2 = 0;
}

static inline __attribute__((always_inline)) void
copy_ipv6_addrs_to_info(struct udp_info *info, struct in6_addr *saddr,
			struct in6_addr *daddr)
{
	u64 *addr;
	addr = (u64 *)saddr;
	info->saddr.ipv6[0] = addr[0];
	info->saddr.ipv6[1] = addr[1];
	addr = (u64 *)daddr;
	info->daddr.ipv6[0] = addr[0];
	info->daddr.ipv6[1] = addr[1];
}

static inline __attribute__((always_inline)) struct udp_info *
udp_port_info(struct udphdr *udp, u64 send)
{
	struct udp_info *info;
	int zero = 0;

	info = (struct udp_info *)map_lookup_elem(&tg_udp_info_heap, &zero);
	if (!info)
		return 0;

	if (send) {
		info->sport = bpf_ntohs(udp->source);
		info->dport = bpf_ntohs(udp->dest);
	} else {
		info->sport = bpf_ntohs(udp->dest);
		info->dport = bpf_ntohs(udp->source);
	}
	info->padding[0] = 0;
	info->padding[1] = 0;
	info->padding[2] = 0;
	return info;
}

static inline __attribute__((always_inline)) struct udp_info *
udp_info(struct iphdr *ip, bool ipv6, struct udphdr *udp, u64 send)
{
	struct udp_info *info;
	int zero = 0;

	info = (struct udp_info *)map_lookup_elem(&tg_udp_info_heap, &zero);
	if (!info || !ip)
		return 0;

	if (send) {
		if (!ipv6) {
			info->saddr.ipv4 = ip->saddr;
			info->daddr.ipv4 = ip->daddr;
			info->ipv6 = false;
		} else {
			copy_ipv6_addrs_to_info(info,
						&((struct ipv6hdr *)ip)->saddr,
						&((struct ipv6hdr *)ip)->daddr);
			info->ipv6 = true;
		}
		info->sport = bpf_ntohs(udp->source);
		info->dport = bpf_ntohs(udp->dest);
	} else {
		if (!ipv6) {
			info->saddr.ipv4 = ip->daddr;
			info->daddr.ipv4 = ip->saddr;
			info->ipv6 = false;
		} else {
			copy_ipv6_addrs_to_info(info,
						&((struct ipv6hdr *)ip)->daddr,
						&((struct ipv6hdr *)ip)->saddr);
			info->ipv6 = true;
		}
		info->sport = bpf_ntohs(udp->dest);
		info->dport = bpf_ntohs(udp->source);
	}
	info->padding[0] = 0;
	info->padding[1] = 0;
	info->padding[2] = 0;
	return info;
}

static inline __attribute__((always_inline)) void
udp_info_init(struct udp_info_value *v)
{
	v->pid = 0;
	v->pid_ktime = 0;
	v->sk_drops = 0;
	v->saddr[0] = 0;
	v->saddr[1] = 0;
	/* Technically, daddr, sport and dport don't need initialising
	 * because if saddr is 0 then we know that the full tuple needs
	 * to be filled in. However, to avoid a bug where the entry is
	 * read from user space and treated as valid, even if the tuple
	 * has yet to be completed, let's initialise them all. These
	 * *_reset() functions only get called once per new socket so
	 * the additional instructions shouldn't be a big overhead.
	 */
	v->daddr[0] = 0;
	v->daddr[1] = 0;
	v->sport = 0;
	v->dport = 0;
	v->skb_consume_misses = 0;
	v->ipv6 = 0;
	WRITE_ONCE(v->ktime, ktime_get_ns());
	v->create_time = 0;
#pragma unroll
	for (int i = 0; i < 8; i++) {
		v->buckets[i] = 0;
	}
	v->latency_sum = 0;
}

static inline __attribute__((always_inline)) void
udp_info_tx_reset(struct udp_info_value *v, int len)
{
	udp_info_init(v);

	v->submitted_bytes = 0;
	v->tx_bytes = len;
	v->consumed_bytes = 0;
	v->rx_bytes = 0;

	v->submitted_segs = 0;
	v->segs_out = len ? 1 : 0;
	v->consumed_segs = 0;
	v->segs_in = 0;
}

static inline __attribute__((always_inline)) void
udp_info_rx_reset(struct udp_info_value *v, int len)
{
	udp_info_init(v);

	v->submitted_bytes = 0;
	v->tx_bytes = 0;
	v->consumed_bytes = 0;
	v->rx_bytes = len;

	v->submitted_segs = 0;
	v->segs_out = 0;
	v->consumed_segs = 0;
	v->segs_in = 1;
}

static inline __attribute__((always_inline)) void
update_tx_value(struct udp_info_value *v, u32 len)
{
	__sync_fetch_and_add(&v->tx_bytes, len);
	__sync_fetch_and_add(&v->segs_out, 1);
	WRITE_ONCE(v->ktime, ktime_get_ns());
}

static inline __attribute__((always_inline)) void
update_rx_value(struct udp_info_value *v, u32 len)
{
	__sync_fetch_and_add(&v->rx_bytes, len);
	__sync_fetch_and_add(&v->segs_in, 1);
	WRITE_ONCE(v->ktime, ktime_get_ns());
}

static inline __attribute__((always_inline)) void
udp_info_submitted_reset(struct udp_info_value *v, int len)
{
	udp_info_init(v);

	v->submitted_bytes = len;
	v->tx_bytes = 0;
	v->consumed_bytes = 0;
	v->rx_bytes = 0;

	v->submitted_segs = len ? 1 : 0;
	v->segs_out = 0;
	v->consumed_segs = 0;
	v->segs_in = 0;
}

static inline __attribute__((always_inline)) void
udp_info_consumed_reset(struct udp_info_value *v, int len)
{
	udp_info_init(v);

	v->submitted_bytes = 0;
	v->tx_bytes = 0;
	v->consumed_bytes = len;
	v->rx_bytes = 0;

	v->submitted_segs = 0;
	v->segs_out = 0;
	v->consumed_segs = len ? 1 : 0;
	v->segs_in = 0;
}

static inline __attribute__((always_inline)) void
update_submitted_value(struct udp_info_value *v, u32 len)
{
	__sync_fetch_and_add(&v->submitted_bytes, len);
	__sync_fetch_and_add(&v->submitted_segs, 1);
	WRITE_ONCE(v->ktime, ktime_get_ns());
}

static inline __attribute__((always_inline)) void
update_consumed_value(struct udp_info_value *v, u32 len)
{
	__sync_fetch_and_add(&v->consumed_bytes, len);
	__sync_fetch_and_add(&v->consumed_segs, 1);
	WRITE_ONCE(v->ktime, ktime_get_ns());
}

static inline __attribute__((always_inline)) void
update_consume_misses(struct udp_info_value *v)
{
	__sync_fetch_and_add(&v->skb_consume_misses, 1);
	WRITE_ONCE(v->ktime, ktime_get_ns());
}
#endif
