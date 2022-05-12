#ifndef __BPF_BURST_PROCESS_H__
#define __BPF_BURST_PROCESS_H__

#include "../lib/bpf_helpers.h"
#include "../lib/networkmsg.h"

#define MAX_UDP_PROCESSES 32768

struct process_network_burst_log {
	__u64 process_start_time;
	__u64 hist_vol;
	__u64 win_vol;
	__u64 last_win_vol;
	__u64 last_packet_time;
	__u64 burst;
	__u64 burst_window_size;
};

struct process_network_burst_config {
	__u64 avg_window_size_ms;
	__u64 window_size;
	__u64 trigger_mult;
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

struct bpf_map_def __attribute__((section("maps"), used))
pn_burst_event_heap = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(struct msg_process_network_burst_event),
	.max_entries = 1,
};

struct bpf_map_def __attribute__((section("maps"), used))
pn_burst_value_heap = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(struct process_network_burst_log),
	.max_entries = 1,
};

struct bpf_map_def __attribute__((section("maps"), used))
pn_burst_config_heap = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(struct process_network_burst_config),
	.max_entries = 1,
};

#define BURST_KEY_PROTO_SHIFT  48
#define BURST_KEY_DIR_SHIFT    32
#define BURST_KEY_SEND_INGRESS 0
#define BURST_KEY_SEND_EGRESS  1
#define NSTOSEC		       1000000000L
#define BURST_END	       0

static inline __attribute__((always_inline)) __u64
tgid_to_burst_key(__u32 tgid, __u64 protocol, __u64 send)
{
	return (__u64)tgid | (protocol << BURST_KEY_PROTO_SHIFT) |
	       ((send & 1) << BURST_KEY_DIR_SHIFT);
}

static inline __attribute__((always_inline)) __u64 burst_start_dir(__u32 start,
								   __u32 dir)
{
	return start | (dir << 16);
}

static inline __attribute__((always_inline)) void
process_burst_check_and_delete(struct msg_process_network_burst_event *e,
			       void *ctx, __u64 protocol, __u64 send,
			       __u64 *cntr)
{
	struct process_network_burst_log *burst_log;

	__u64 burst_key = tgid_to_burst_key(e->key.pid, protocol, send);
	burst_log = map_lookup_elem(&pn_burst_map, &burst_key);
	if (burst_log && burst_log->burst) {
		// Currently in burst state, so send burst end event
		e->burst_start_dir = burst_start_dir(BURST_END, send);
		e->protocol = protocol;
		e->hist_avg = (burst_log->hist_vol + burst_log->last_win_vol +
			       burst_log->win_vol) *
			      1000000000 / (e->common.ktime - e->key.ktime);
		perf_event_output(
			ctx, &tcpmon_map, BPF_F_CURRENT_CPU, e,
			sizeof(struct msg_process_network_burst_event));
	}

	int err = map_delete_elem(&pn_burst_map, &burst_key);
	if (!err && cntr)
		*cntr = *cntr - 1;
}

static inline __attribute__((always_inline)) void
process_burst_map_delete(void *ctx, __u32 pid)
{
	int zero = 0;
	__u64 *cntr;
	struct msg_process_network_burst_event *val;
	struct execve_map_value *process;

	process = execve_map_get(pid);
	val = map_lookup_elem(&pn_burst_event_heap, &zero);
	cntr = map_lookup_elem(&pn_burst_map_stats, &zero);

	if (val && process) {
		// Complete common event details.
		*val = (struct msg_process_network_burst_event){
			.common.op = MSG_OP_IPV4_PROCESS_BURST,
			.common.size =
				sizeof(struct msg_process_network_burst_event),
			.common.ktime = ktime_get_ns(),
			.key.pid = pid,
			.key.ktime = process->key.ktime,
			.protocol = 0,
			.burst_start_dir = 0,
			.window_size = 0,
			.hist_avg = 0,
			.hist_trigger = 0,
			.window_avg = 0,
		};

		process_burst_check_and_delete(val, ctx, IPPROTO_UDP,
					       BURST_KEY_SEND_INGRESS, cntr);
		process_burst_check_and_delete(val, ctx, IPPROTO_UDP,
					       BURST_KEY_SEND_EGRESS, cntr);
		process_burst_check_and_delete(val, ctx, IPPROTO_TCP,
					       BURST_KEY_SEND_INGRESS, cntr);
		process_burst_check_and_delete(val, ctx, IPPROTO_TCP,
					       BURST_KEY_SEND_EGRESS, cntr);
	}
}

static inline __attribute__((always_inline)) void
init_burst_log(u64 burst_key, u64 process_start_time, u64 vol,
	       u64 current_time_ns, u64 burst_window_size)
{
	struct process_network_burst_log *burst_log;
	int err, zero = 0;
	u64 *cntr;

	burst_log = map_lookup_elem(&pn_burst_value_heap, &zero);
	if (!burst_log)
		return;

	*burst_log = (struct process_network_burst_log){
		.process_start_time = process_start_time,
		.hist_vol = 0,
		.win_vol = vol,
		.last_win_vol = 0,
		.last_packet_time = current_time_ns,
		.burst = false,
		.burst_window_size = burst_window_size,
	};

	err = map_update_elem(&pn_burst_map, &burst_key, burst_log,
			      BPF_NOEXIST);
	if (!err && (cntr = map_lookup_elem(&pn_burst_map_stats, &zero)))
		*cntr = *cntr + 1;
}

// There are two critical design decisions with the burst monitor.
// First, if we wanted to implement a sliding window approach (comparing
// sliding window average to the historical long-term average), then we
// would need to temporarily store payload sizes against time stamps, to
// allow us to calculate the volume within the sliding window. This
// approach would require a data structure where older entries could be
// aged off and subtracted from a total (not easy in BPF) or the
// entire data structure would need to be traversed to calculate the
// current window volume (not nice in BPF). Additionally, sizing the data
// structure would not be trivial, potentially leading to missing data.
//
// The solution is to use fixed-position windows. By dividing time since
// the process started into a series of (non-overlapping) windows, we can
// simply deal with packets that arrived before the current window
// (historical data), or within our current window. It is trivial to calc
// which a packet is from its arrival time.
//
// Second, we need to account for multiple cores accessing the global
// historical values. Switching from one fixed-position window to the next
// must only happen in one thread, and if multiple threads collide, then
// this approach would fail.

static inline __attribute__((always_inline)) void
process_network_burst(void *ctx, struct execve_map_value *process, u64 protocol,
		      u64 send, u64 vol, struct process_network_burst_config *c)
{
	u64 burst_key;
	struct process_network_burst_log *burst_log;

	u64 current_time_ns = ktime_get_ns();

	burst_key = tgid_to_burst_key(process->key.pid, protocol, send);

	burst_log = map_lookup_elem(&pn_burst_map, &burst_key);
	if (!burst_log) {
		// First packet for this process in this direction, for this protocol.
		// This could be racy in the sense that multiple cores could initialise the
		// global entry for this process.
		init_burst_log(burst_key, process->key.ktime, vol,
			       current_time_ns, c->avg_window_size_ms);
		return;
	}

	u64 ns_since_win_start =
		(current_time_ns - process->key.ktime) % c->window_size;
	u64 current_win_start_ns = current_time_ns - ns_since_win_start;
	u64 last_win_start_ns = current_win_start_ns - c->window_size;

	u32 old_burst = READ_ONCE(burst_log->burst);

	// Read and write the last packet time with atomic instructions
	// to reduce the race in the 'if' statement. Once the read/write
	// has occurred, subsequent threads will see a last packet time
	// in the current window and simply add to that. There is a slim
	// chance of multiple threads arriving within 1 instruction of
	// each other and all attempting to update the windows/history,
	// but this is considered unlikely.
	//
	// If the unlikely race condition occurs, both threads will attempt
	// to move the current window to the last window and the last window
	// to history, resulting in the current window missing one packet's
	// volume, and the old window being added twice to last or history.
	// This will cause the averages to be wrong, so the effect will be
	// skewed by the historical averages and the packet volumes -
	// sometimes it would matter, and other times not so much.
	u64 last_packet_time = READ_ONCE(burst_log->last_packet_time);
	WRITE_ONCE(burst_log->last_packet_time, current_time_ns);

	if (last_packet_time > current_win_start_ns) {
		// Add packet volume to current window.
		__sync_fetch_and_add(&burst_log->win_vol, vol);
	} else {
		// Volume currently accumulated in current window is old.
		if (last_packet_time > last_win_start_ns) {
			// The current window volume is actually for the last window
			// (e.g. a new window has started since the last packet was
			// received).
			//
			// Move the last window to history, current window to last,
			// and store current packet in new current window.
			__sync_fetch_and_add(&burst_log->hist_vol,
					     burst_log->last_win_vol);
			WRITE_ONCE(burst_log->last_win_vol,
				   READ_ONCE(burst_log->win_vol));
			WRITE_ONCE(burst_log->win_vol, vol);
		} else {
			// The current window volume is actually older than the
			// last window and therefore historic (e.g. two windows
			// have started since the last packet was received).
			//
			// Move the last window and current window to history,
			// and store the current packet in new current window.
			// Also, any existing burst must be over.
			__sync_fetch_and_add(&burst_log->hist_vol,
					     burst_log->last_win_vol);
			__sync_fetch_and_add(&burst_log->hist_vol,
					     burst_log->win_vol);
			WRITE_ONCE(burst_log->win_vol, vol);
			// Zero the last window
			WRITE_ONCE(burst_log->last_win_vol, 0);
			old_burst = 0;
		}
	}

	u64 hist_vol = READ_ONCE(burst_log->hist_vol);
	u64 win_vol = READ_ONCE(burst_log->win_vol);
	u64 last_win_vol = READ_ONCE(burst_log->last_win_vol);
	u64 hist_avg =
		(hist_vol * NSTOSEC) / (last_win_start_ns - process->key.ktime);
	u64 hist_avg_trigger = (hist_avg * c->trigger_mult) / 100;

	// Check if the average volume over the last complete window and the current
	// partial window exceeds the trigger threshold. This approach provides a
	// fair average of the current rate.
	u64 new_win_rate = ((last_win_vol + win_vol) * NSTOSEC) /
			   (c->window_size + ns_since_win_start);
	if (old_burst ^ (new_win_rate > hist_avg_trigger)) {
		// If we were already bursting and no longer are, or weren't bursting
		// but now are (XOR) then emit event.
		struct msg_process_network_burst_event *val;
		int zero = 0;

		val = map_lookup_elem(&pn_burst_event_heap, &zero);
		if (!val)
			return;

		*val = (struct msg_process_network_burst_event){
			.common.op = MSG_OP_IPV4_PROCESS_BURST,
			.common.size =
				sizeof(struct msg_process_network_burst_event),
			.common.ktime = current_time_ns,
			.key.pid = process->key.pid,
			.key.ktime = process->key.ktime,
			.protocol = protocol,
			.burst_start_dir =
				burst_start_dir(old_burst == 0, send),
			.window_size = c->avg_window_size_ms,
			.hist_avg = hist_avg,
			.hist_trigger = hist_avg_trigger,
			.window_avg = new_win_rate,
		};
		perf_event_output(
			ctx, &tcpmon_map, BPF_F_CURRENT_CPU, val,
			sizeof(struct msg_process_network_burst_event));
		WRITE_ONCE(burst_log->burst, (old_burst == 0));
	}
}

#endif // __BPF_BURST_PROCESS_H__
