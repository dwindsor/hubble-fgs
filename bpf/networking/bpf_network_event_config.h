#ifndef __BPF_NETWORK_EVENT_CONFIG_H__
#define __BPF_NETWORK_EVENT_CONFIG_H__

#include "../lib/bpf_helpers.h"

struct tcp_event_disable_config {
	__u8 disableConnect;
	__u8 disableClose;
	__u8 disableAccept;
	__u8 disableListen;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct tcp_event_disable_config);
	__uint(max_entries, 1);
} tg_event_disable_config SEC(".maps");

#endif
