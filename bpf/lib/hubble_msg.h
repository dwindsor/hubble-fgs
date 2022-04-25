#ifndef __HUBBLE_MSG_
#define __HUBBLE_MSG_

#include "msg_types.h"
#include "common.h"
#include "process.h"
#include "bpf_helpers.h"

struct msg_calltrace {
	__u64 stack[16];
	int32_t ret;
} __attribute__((packed));

struct msg_creds {
	struct msg_common common;
	struct msg_execve_key current;
	struct msg_capabilities caps;
};

struct event {
	int event;
};

#ifdef BTF
struct {
	unsigned int (*type)[BPF_MAP_TYPE_PERF_EVENT_ARRAY];
	unsigned int (*key_size)[sizeof(int)];
	unsigned int (*value_size)[sizeof(struct event)];
} tcpmon_map __attribute__((section((".maps")), used));
#else
struct bpf_map_def __attribute__((section("maps"), used)) tcpmon_map = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(struct event),
};
#endif // BTF

#endif // __HUBBLE_MSG_
