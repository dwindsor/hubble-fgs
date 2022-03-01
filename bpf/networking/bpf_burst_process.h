#ifndef __BPF_BURST_PROCESS_H__
#define __BPF_BURST_PROCESS_H__

#define MAX_UDP_PROCESSES 32768

struct process_network_burst_log {
        __u64 hist_vol;
        __u64 win_vol;
        __u64 last_win_vol;
        __u64 last_packet_time;
        __u32 burst;
};

struct bpf_map_def __attribute__((section("maps"), used)) pn_burst_map = {
        .type = BPF_MAP_TYPE_LRU_HASH,
        .key_size = sizeof(__u64),
        .value_size = sizeof(struct process_network_burst_log),
        .max_entries = MAX_UDP_PROCESSES,
};

struct bpf_map_def __attribute__((section("maps"), used)) pn_burst_map_stats = {
        .type = BPF_MAP_TYPE_PERCPU_ARRAY,
        .key_size = sizeof(int),
        .value_size = sizeof(__u64),
        .max_entries = 1,
};

#define BURST_KEY_PROTO_SHIFT 48
#define BURST_KEY_DIR_SHIFT 32
#define BURST_KEY_SEND_INGRESS 0
#define BURST_KEY_SEND_EGRESS 1

static inline __attribute__((always_inline))
__u64 pid_to_udp_burst_key(__u32 pid, __u32 send)
{
        return (__u64)pid | ((__u64)IPPROTO_UDP << BURST_KEY_PROTO_SHIFT)
		| ((__u64)(send & 1) << BURST_KEY_DIR_SHIFT);
}

static inline __attribute__((always_inline))
__u64 pid_to_tcp_burst_key(__u32 pid, __u32 send)
{
        return (__u64)pid | ((__u64)IPPROTO_TCP << BURST_KEY_PROTO_SHIFT)
		| ((__u64)(send & 1) << BURST_KEY_DIR_SHIFT);
}

static inline __attribute__((always_inline))
__u64 burst_start_dir(__u32 start, __u32 dir)
{
        return start | (dir << 16);
}

static inline __attribute__((always_inline))
void map_delete_process_burst(__u32 pid)
{
	int err, zero = 0;
	__u64 *cntr;

	cntr = map_lookup_elem(&pn_burst_map_stats, &zero);

	__u64 burst_key = pid_to_udp_burst_key(pid, BURST_KEY_SEND_INGRESS);

        err = map_delete_elem(&pn_burst_map, &burst_key);
	if (!err && cntr)
		*cntr = *cntr - 1;

	burst_key = pid_to_udp_burst_key(pid, BURST_KEY_SEND_EGRESS);
        err = map_delete_elem(&pn_burst_map, &burst_key);
	if (!err && cntr)
		*cntr = *cntr - 1;
}

#endif // __BPF_BURST_PROCESS_H__
