#ifndef __BPF_PROCESS_NETWORK_WATERMARKS_H__
#define __BPF_PROCESS_NETWORK_WATERMARKS_H__

#include "../lib/bpf_helpers.h"
#include "../lib/networkmsg.h"
#include "../lib/iso_msg_types.h"
#include "cookie.h"
#include "bpf_tracing.h"

#define MAX_UDP_PROCESSES 32768

struct process_network_watermarks_log {
	__u64 process_start_time;
	__u64 hist_vol;
	__u64 win_vol;
	__u64 last_win_vol;
	__u64 last_packet_time;
	__u64 watermarks_state;
	__u64 watermarks_window_size;
};

struct process_network_watermarks_config {
	__u64 avg_window_size_ms;
	__u64 window_size;
	__u64 burst_trigger_mult;
	__u64 dip_trigger_mult;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u64);
	__type(value, struct process_network_watermarks_log);
	__uint(max_entries, MAX_UDP_PROCESSES);
} tg_pn_watermarks_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, __u64);
	__uint(max_entries, 1);
} tg_pn_watermarks_map_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct msg_process_network_watermarks_event);
	__uint(max_entries, 1);
} tg_pn_watermarks_event_heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct process_network_watermarks_log);
	__uint(max_entries, 1);
} tg_pn_watermarks_value_heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct process_network_watermarks_config);
	__uint(max_entries, 1);
} tg_pn_watermarks_config_heap SEC(".maps");

#define WATERMARKS_KEY_PROTO_SHIFT  48
#define WATERMARKS_KEY_DIR_SHIFT    32
#define WATERMARKS_KEY_SEND_INGRESS 0
#define WATERMARKS_KEY_SEND_EGRESS  1
#define NSTOSEC			    1000000000L
#define WATERMARKS_END		    0
#define WATERMARKS_START	    1
#define WATERMARKS_BURST	    0
#define WATERMARKS_DIP		    1
#define WATERMARKS_STATE_NONE	    0
#define WATERMARKS_STATE_BURST	    1
#define WATERMARKS_STATE_DIP	    2

static inline __attribute__((always_inline)) __u8
watermarks_state_to_type(__u8 state)
{
	switch (state) {
	case WATERMARKS_STATE_BURST:
		return WATERMARKS_BURST;
	case WATERMARKS_STATE_DIP:
		return WATERMARKS_DIP;
	}
	return 255;
}

static inline __attribute__((always_inline)) __u64
tgid_to_watermarks_key(__u32 tgid, __u64 protocol, __u64 send)
{
	return (__u64)tgid | (protocol << WATERMARKS_KEY_PROTO_SHIFT) |
	       ((send & 1) << WATERMARKS_KEY_DIR_SHIFT);
}

static inline __attribute__((always_inline)) void
process_watermarks_check_and_delete(struct msg_process_network_watermarks_event *e,
				    void *ctx, __u64 protocol, __u64 send,
				    __u64 *cntr)
{
	struct process_network_watermarks_log *watermarks_log;

	__u64 watermarks_key =
		tgid_to_watermarks_key(e->key.pid, protocol, send);
	watermarks_log = map_lookup_elem(&tg_pn_watermarks_map, &watermarks_key);
	if (watermarks_log && watermarks_log->watermarks_state) {
		// Currently in burst state, so send burst end event
		e->direction = send;
		e->state = WATERMARKS_END;
		e->type = watermarks_state_to_type(watermarks_log->watermarks_state);
		e->protocol = protocol;
		e->hist_avg = (watermarks_log->hist_vol +
			       watermarks_log->last_win_vol +
			       watermarks_log->win_vol) *
			      1000000000 / (e->common.ktime - e->key.ktime);
		perf_event_output(
			ctx, &tcpmon_map, BPF_F_CURRENT_CPU, e,
			sizeof(struct msg_process_network_watermarks_event));
	}

	int err = map_delete_elem(&tg_pn_watermarks_map, &watermarks_key);
	if (!err && cntr)
		*cntr = *cntr - 1;
}

static inline __attribute__((always_inline)) void
process_watermarks_map_delete(void *ctx, __u32 tgid)
{
	int zero = 0;
	__u64 *cntr;
	struct msg_process_network_watermarks_event *val;
	struct execve_map_value *process;

	process = execve_map_get_noinit(tgid);
	val = map_lookup_elem(&tg_pn_watermarks_event_heap, &zero);
	cntr = map_lookup_elem(&tg_pn_watermarks_map_stats, &zero);

	if (val && process) {
		// Complete common event details.
		*val = (struct msg_process_network_watermarks_event){
			.common.op = ISO_MSG_OP_PROCESS_NETWORK_WATERMARK,
			.common.size =
				sizeof(struct msg_process_network_watermarks_event),
			.common.ktime = ktime_get_ns(),
			.key.pid = tgid,
			.key.ktime = process->key.ktime,
			.protocol = 0,
			.direction = 0,
			.state = 0,
			.type = 0,
			.window_size = 0,
			.hist_avg = 0,
			.hist_burst_trigger = 0,
			.hist_dip_trigger = 0,
			.window_avg = 0,
		};

		process_watermarks_check_and_delete(val, ctx, IPPROTO_UDP,
						    WATERMARKS_KEY_SEND_INGRESS, cntr);
		process_watermarks_check_and_delete(val, ctx, IPPROTO_UDP,
						    WATERMARKS_KEY_SEND_EGRESS, cntr);
		process_watermarks_check_and_delete(val, ctx, IPPROTO_TCP,
						    WATERMARKS_KEY_SEND_INGRESS, cntr);
		process_watermarks_check_and_delete(val, ctx, IPPROTO_TCP,
						    WATERMARKS_KEY_SEND_EGRESS, cntr);
	}
}

static inline __attribute__((always_inline)) void
init_watermarks_log(u64 watermarks_key, u64 process_start_time, u64 vol,
		    u64 current_time_ns, u64 watermarks_window_size)
{
	struct process_network_watermarks_log *watermarks_log;
	int err, zero = 0;
	u64 *cntr;

	watermarks_log = map_lookup_elem(&tg_pn_watermarks_value_heap, &zero);
	if (!watermarks_log)
		return;

	*watermarks_log = (struct process_network_watermarks_log){
		.process_start_time = process_start_time,
		.hist_vol = 0,
		.win_vol = vol,
		.last_win_vol = 0,
		.last_packet_time = current_time_ns,
		.watermarks_state = false,
		.watermarks_window_size = watermarks_window_size,
	};

	err = map_update_elem(&tg_pn_watermarks_map, &watermarks_key,
			      watermarks_log, BPF_NOEXIST);
	if (!err && (cntr = map_lookup_elem(&tg_pn_watermarks_map_stats, &zero)))
		*cntr = *cntr + 1;
}

// There are two critical design decisions with the watermarks monitor.
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
process_network_watermarks(void *ctx, struct socketmap_value *process, u64 protocol,
			   u64 send, u64 vol, struct process_network_watermarks_config *c)
{
	u64 watermarks_key;
	struct process_network_watermarks_log *watermarks_log;

	u64 current_time_ns = ktime_get_ns();

	if (execve_map_get_noinit(process->key.pid) == 0)
		// If the process is not in the execve map, then this means the
		// process has ended, and this is a stray packet arriving on the
		// socket after the exit; and it also means that the socket
		// cookie is still in the socket map, which means the socket
		// wasn't closed, but the process exited while the socket was
		// still open.
		return;

	watermarks_key =
		tgid_to_watermarks_key(process->key.pid, protocol, send);

	watermarks_log = map_lookup_elem(&tg_pn_watermarks_map, &watermarks_key);
	if (!watermarks_log) {
		// First packet for this process in this direction, for this protocol.
		// This could be racy in the sense that multiple cores could initialise the
		// global entry for this process.
		init_watermarks_log(watermarks_key, process->key.ktime, vol,
				    current_time_ns, c->avg_window_size_ms);
		return;
	}

	u64 ns_since_win_start =
		(current_time_ns - process->key.ktime) % c->window_size;
	u64 current_win_start_ns = current_time_ns - ns_since_win_start;
	u64 last_win_start_ns = current_win_start_ns - c->window_size;

	u32 old_watermarks_state = READ_ONCE(watermarks_log->watermarks_state);

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
	u64 last_packet_time = READ_ONCE(watermarks_log->last_packet_time);
	WRITE_ONCE(watermarks_log->last_packet_time, current_time_ns);

	if (last_packet_time > current_win_start_ns) {
		// Add packet volume to current window.
		__sync_fetch_and_add(&watermarks_log->win_vol, vol);
	} else {
		// Volume currently accumulated in current window is old.
		if (last_packet_time > last_win_start_ns) {
			// The current window volume is actually for the last window
			// (e.g. a new window has started since the last packet was
			// received).
			//
			// Move the last window to history, current window to last,
			// and store current packet in new current window.
			__sync_fetch_and_add(&watermarks_log->hist_vol,
					     watermarks_log->last_win_vol);
			WRITE_ONCE(watermarks_log->last_win_vol,
				   READ_ONCE(watermarks_log->win_vol));
			WRITE_ONCE(watermarks_log->win_vol, vol);
		} else {
			// The current window volume is actually older than the
			// last window and therefore historic (e.g. two windows
			// have started since the last packet was received).
			//
			// Move the last window and current window to history,
			// and store the current packet in new current window.
			// Also, any existing burst must be over.
			__sync_fetch_and_add(&watermarks_log->hist_vol,
					     watermarks_log->last_win_vol);
			__sync_fetch_and_add(&watermarks_log->hist_vol,
					     watermarks_log->win_vol);
			WRITE_ONCE(watermarks_log->win_vol, vol);
			// Zero the last window
			WRITE_ONCE(watermarks_log->last_win_vol, 0);
			old_watermarks_state = 0;
		}
	}

	u64 hist_vol = READ_ONCE(watermarks_log->hist_vol);
	u64 win_vol = READ_ONCE(watermarks_log->win_vol);
	u64 last_win_vol = READ_ONCE(watermarks_log->last_win_vol);
	u64 hist_avg =
		(hist_vol * NSTOSEC) / (last_win_start_ns - process->key.ktime);
	u64 hist_burst_avg_trigger = (hist_avg * c->burst_trigger_mult) / 100;
	u64 hist_dip_avg_trigger = (hist_avg * c->dip_trigger_mult) / 100;

	// Check if the average volume over the last complete window and the current
	// partial window exceeds the burst trigger threshold or fails to reach the
	// dip trigger threshold. This approach provides a fair average of the
	// current rate.
	u64 new_win_rate = ((last_win_vol + win_vol) * NSTOSEC) /
			   (c->window_size + ns_since_win_start);

	// Check if: a) we were in a burst but are no longer, or not in a burst and now are; or
	// b) we were in a dip but are no longer, or not in a dip and now are.
	// If so, we need to send an event to mark the start or end of a burst or dip.
	if (
		((old_watermarks_state == WATERMARKS_STATE_BURST) ^ (new_win_rate > hist_burst_avg_trigger)) ||
		((old_watermarks_state == WATERMARKS_STATE_DIP) ^ (new_win_rate < hist_dip_avg_trigger))) {
		struct msg_process_network_watermarks_event *val;
		int zero = 0;

		val = map_lookup_elem(&tg_pn_watermarks_event_heap, &zero);
		if (!val)
			return;

		*val = (struct msg_process_network_watermarks_event){
			.common.op = ISO_MSG_OP_PROCESS_NETWORK_WATERMARK,
			.common.size =
				sizeof(struct msg_process_network_watermarks_event),
			.common.ktime = current_time_ns,
			.key.pid = process->key.pid,
			.key.ktime = process->key.ktime,
			.protocol = protocol,
			.direction = send,
			.window_size = c->avg_window_size_ms,
			.hist_avg = hist_avg,
			.hist_burst_trigger = hist_burst_avg_trigger,
			.hist_dip_trigger = hist_dip_avg_trigger,
			.window_avg = new_win_rate,
		};

		u32 new_watermarks_state = 0;

		switch (old_watermarks_state) {
		case WATERMARKS_STATE_BURST:
			// send burst end.
			val->type = WATERMARKS_BURST;
			val->state = WATERMARKS_END;
			perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, val,
					  sizeof(struct msg_process_network_watermarks_event));
			new_watermarks_state = WATERMARKS_STATE_NONE;
			// check if dip start needed.
			if (new_win_rate < hist_dip_avg_trigger) {
				val->type = WATERMARKS_STATE_DIP;
				val->state = WATERMARKS_START;
				perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, val,
						  sizeof(struct msg_process_network_watermarks_event));
				new_watermarks_state = WATERMARKS_STATE_DIP;
			}
			break;
		case WATERMARKS_STATE_DIP:
			// send dip end.
			val->type = WATERMARKS_DIP;
			val->state = WATERMARKS_END;
			perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, val,
					  sizeof(struct msg_process_network_watermarks_event));
			new_watermarks_state = WATERMARKS_STATE_NONE;
			// check if burst start needed.
			if (new_win_rate > hist_burst_avg_trigger) {
				val->type = WATERMARKS_BURST;
				val->state = WATERMARKS_START;
				perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, val,
						  sizeof(struct msg_process_network_watermarks_event));
				new_watermarks_state = WATERMARKS_STATE_BURST;
			}
			break;
		default:
			if (new_win_rate > hist_burst_avg_trigger) {
				val->type = WATERMARKS_BURST;
				val->state = WATERMARKS_START;
				new_watermarks_state = WATERMARKS_STATE_BURST;
			} else {
				val->type = WATERMARKS_DIP;
				val->state = WATERMARKS_START;
				new_watermarks_state = WATERMARKS_STATE_DIP;
			}
			perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, val,
					  sizeof(struct msg_process_network_watermarks_event));
		}

		WRITE_ONCE(watermarks_log->watermarks_state, new_watermarks_state);
	}
}

#endif // __BPF_BURST_PROCESS_H__
