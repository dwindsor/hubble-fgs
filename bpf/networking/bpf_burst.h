#ifndef __BPF_BURST_H__
#define __BPF_BURST_H__

struct bpf_map_def __attribute__((section("maps"), used)) pn_burst_event_heap = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(struct msg_process_network_burst_event),
	.max_entries = 1,
};

struct bpf_map_def __attribute__((section("maps"), used)) pn_burst_value_heap = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(struct process_network_burst_log),
	.max_entries = 1,
};

#endif // __BPF_BURST_H__
