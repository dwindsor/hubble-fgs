#ifndef __DISPACHER_H__
#define __DISPACHER_H__

/*
 * This header file implememts the dispatcher for FIM programs. For now this is only implemented
 * for path-based programs, but this can easily extended for inode-based programs as well.
 *
 * Let's take as an example a the fmod_ret/security_file_permission hook. Without using the
 * dispatcher, we load and attach a new program (with its associated maps) for each tracing policy.
 * It is obvious, that in the case where this program does not match a specific file operation,
 * just calling that and checking the selectors (and pod selectors) introduces overheads. The idea
 * is to have a single program attached to the hook that we care about and by using tail calls run
 * only the programs that implement the specific details of each tracing policy.
 *
 * When FIM dispatcher is enabled, we attach a single program (i.e. fmod_ret_dispatcher.c for the
 * previous example) before loading any tracing policies. This program is the entry point and just
 * calls handle_dispatcher() which is implemented in that file. This call, first gets the cgroup-id
 * of the caller. Based on that, it used policy_filter_cgroup_maps map to get a map with all the
 * tracing policy ids that needs to run for this specific cgroup-id.
 *
 * All programs are stored in a BPF_MAP_TYPE_PROG_ARRAY map named fim_tail_calls. As now we have
 * the tracing policy ids and we also have the map with tail calls, we need a way to translate a
 * tracing policy id to a tail call index which shows us in which index of the tail call map, each
 * program exists. The translation is done by using the policy_id_to_tail_index map.
 *
 * So when the user applies a new tracing policy for FIM, the sensor, load a program (with its
 * maps) related to the new tracing policy. Then it adds the program to the tail call map
 * (fim_tail_calls) and adds a tracing policy id to tail call index (policy_id_to_tail_index).
 *
 * Once handle_dispatcher() call find the programs that needs to run, it starts executing those
 * by using tail calls. This means that we always runs all the programs that match the specific
 * cgroup-id. When all programs are executed, the last tail call executes again the entry point.
 * This is mainly needed in the case where we have enforcement. So, if any of the tracing policies
 * that we run needs to block the call, the final call to the entry point returns a negative value
 * (these are lsm or fmod_ret programs) and block the operation.
 */

#include "vmlinux.h"
#include "api.h"
#include "bpf_tracing.h"

#define MAX_POLICY_IDS_SHIFT 5
#define MAX_POLICY_IDS	     (1 << MAX_POLICY_IDS_SHIFT)
#define MAX_POLICY_IDS_MASK  (MAX_POLICY_IDS - 1)

struct dis_ctrl {
	__u32 in_progress;
	__s32 retval;
	__u32 policy_ids[MAX_POLICY_IDS]; // max policy ids match the maximum number of tail calls (i.e. MAX_TAIL_CALL_CNT which is 33)
	__u32 curr_policy_id;
	__u32 num_policy_ids;
};

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1024);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} fim_tail_calls SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct dis_ctrl);
	__uint(max_entries, 1);
} dis_ctx_heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1024);
} policy_id_to_tail_index SEC(".maps");

static inline __attribute__((always_inline)) void do_tail_call_if_needed(void *ctx, __s32 retval)
{
	__u32 *tail_id_ptr, tail_id, policy_id;
	__u32 zero = 0;
	struct dis_ctrl *dis_ctx;

	dis_ctx = map_lookup_elem(&dis_ctx_heap, &zero);
	if (!dis_ctx)
		return;

	// nothing to do here
	if (!dis_ctx->in_progress)
		return;

	// if retval != 0 this means that it is -EPERM and we should block the operation
	if (retval)
		dis_ctx->retval = retval;

	// we are done and we need to go back to the initial call
	if (dis_ctx->curr_policy_id == dis_ctx->num_policy_ids) {
		tail_call(ctx, &fim_tail_calls, 0);
	}

	// get the next policy id
	policy_id = dis_ctx->policy_ids[dis_ctx->curr_policy_id & MAX_POLICY_IDS_MASK];
	dis_ctx->curr_policy_id++;

	// translate policy_id to tail_id
	tail_id_ptr = map_lookup_elem(&policy_id_to_tail_index, &policy_id);
	if (!tail_id_ptr)
		return;

	tail_id = *tail_id_ptr;

	tail_call(ctx, &fim_tail_calls, tail_id);
}

static inline __attribute__((always_inline)) int handle_tail_call(void *ctx, __s32 retval)
{
	do_tail_call_if_needed(ctx, retval);
	return retval < 0 ? -EPERM : 0;
}

static long dispatcher_cb(void *map, const void *key, void *val, void *ctx)
{
	__u32 zero = 0, policy_id = *(__u32 *)key;
	struct dis_ctrl *dis_ctx;

	dis_ctx = map_lookup_elem(&dis_ctx_heap, &zero);
	if (!dis_ctx)
		return 0;

	dis_ctx->policy_ids[dis_ctx->num_policy_ids &= MAX_POLICY_IDS_MASK] = policy_id;
	dis_ctx->num_policy_ids++;

	return 0;
}

static inline __attribute__((always_inline)) int handle_dispatcher(void *ctx)
{
	__u32 *tail_id_ptr, tail_id, policy_id, zero = 0;
	struct dis_ctrl *dis_ctx;
	__u64 cgroupid = 0;
	void *policy_map;

	cgroupid = tg_get_current_cgroup_id(); // what about bpf_get_current_cgroup_id helper?
	if (!cgroupid)
		return 0;

	policy_map = map_lookup_elem(&policy_filter_cgroup_maps, &cgroupid);
	if (!policy_map)
		return 0;

	dis_ctx = map_lookup_elem(&dis_ctx_heap, &zero);
	if (!dis_ctx)
		return 0;

	if (dis_ctx->in_progress) {
		// back from all tail calls
		dis_ctx->in_progress = 0;
		return dis_ctx->retval < 0 ? -EPERM : 0;
	}

	// reset everything in dis_ctx
	memset(dis_ctx, 0, sizeof(struct dis_ctrl));

	for_each_map_elem(policy_map, &dispatcher_cb, 0, 0);

	// no policies to apply
	if (dis_ctx->num_policy_ids == 0)
		return 0;

	dis_ctx->in_progress = 1;
	policy_id = dis_ctx->policy_ids[dis_ctx->curr_policy_id & MAX_POLICY_IDS_MASK];
	dis_ctx->curr_policy_id++;

	// translate policy_id to tail_id
	tail_id_ptr = map_lookup_elem(&policy_id_to_tail_index, &policy_id);
	if (!tail_id_ptr)
		return 0;

	tail_id = *tail_id_ptr;

	tail_call(ctx, &fim_tail_calls, tail_id);

	return 0;
}

#endif /* __DISPACHER_H__ */
