#ifndef __PROCESS_LPM__
#define __PROCESS_LPM__

#include "parsers/dns/dns_pstree.h"

struct addr4_lpm_trie {
	__u32 prefix;
	__u32 addr;
};

struct addr6_lpm_trie {
	__u32 prefix;
	__u32 addr[4];
};

struct lpm_endpoint_id_value {
	uint64_t id;
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 1);
	__type(key, struct addr4_lpm_trie); // Need to specify as byte array as wouldn't take struct as key type
	__type(value, struct lpm_endpoint_id_value);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} addr4lpm_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 1);
	__type(key, struct addr6_lpm_trie); // Need to specify as byte array as wouldn't take struct as key type
	__type(value, struct lpm_endpoint_id_value);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} addr6lpm_map SEC(".maps");

uint64_t lpm_ipkey_lookup(struct ip_addr *ip_key)
{
	struct lpm_endpoint_id_value *val;

	if (!ip_key)
		return 0;

	if (ip_key->af_inet6) {
		struct addr6_lpm_trie key = { 0 };

		key.prefix = 128;
		__bpf_memcpy_builtin(key.addr, ip_key->addr, sizeof(key.addr));
		val = map_lookup_elem(&addr6lpm_map, &key);
	} else {
		struct addr4_lpm_trie key;

		key.prefix = 32;
		key.addr = ip_key->addr[0] & 0xffffffff;
		val = map_lookup_elem(&addr4lpm_map, &key);
	}
	if (!val)
		return 0;

	return val->id;
}
#endif
