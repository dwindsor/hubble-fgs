#ifndef _CONFIG__
#define _CONFIG__

#include "vmlinux.h"
#include "bpf_helpers.h"

struct cfg_value {
	__u8 icmp_tracking_enabled;
	__u8 icmp_net_match;
	__u8 pad[6];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct cfg_value);
	__uint(max_entries, 1);
} tg_cfg_map SEC(".maps");

#endif
