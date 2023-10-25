#ifndef __ICMP_COOKIE_H_
#define __ICMP_COOKIE_H_

#include "vmlinux.h"
#include "../lib/iso_msg_types.h"
#include "../lib/networkmsg.h"
#include "../lib/tlsmsg.h"
#include "../lib/config.h"
#include "../lib/address_family.h"
#include "../cookie.h"

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

#endif
