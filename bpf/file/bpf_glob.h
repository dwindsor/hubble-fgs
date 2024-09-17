#ifndef __BPF_GLOB_H__
#define __BPF_GLOB_H__

#include "vmlinux.h"
#include "api.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"

// the maximum number of possible next states for each character in that inpput path
#define INNER_MAX_STATES 128

// this acts as a temporary buffer for keeping the possible states for each characters
// we need at least 2 for each function invocation (i.e. one for the current states and
// one for the next states). Furthermore, we use one part of these temporary buffers per
// core. This means that the max_entries of the outer map should be 2 * number_of_cores,
// and this is allocated from the user-space. We use the bpf_get_smp_processor_id eBPF helper
// to get out cpu_id.
//
// Another idea was to use BPF_MAP_TYPE_PERCPU_HASH. But this didn't seem to work as expected.
// So we choose this for now and will investigate on what is missing to make BPF_MAP_TYPE_PERCPU_HASH
// work (or if this is not possible at all).
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, 1); // user set this
	__type(key, __u32);
	__array(
		values, struct {
			__uint(type, BPF_MAP_TYPE_HASH);
			__uint(max_entries, INNER_MAX_STATES);
			__type(key, __s32);
			__type(value, __s32);
		});
} glob_temp_maps SEC(".maps");

static long BPF_FUNC(for_each_map_elem, void *map, void *callback_fn, void *callback_ctx, __u64 flags);

struct loop_ctx {
	void *currentStates; // current set of states
	void *nextStatesSet; // next set of states
	void *patternMap; // the map that contains the states of the FSM
	u32 map_idx; // the id of the map to use in the current iteration (0 or 1)
	char *path; // the path to match
	u32 len; // the len of the path to match
	u8 err; // != 0 in case of errors
	u8 c; // teh current character of the path
	u8 isFinal; // 1 if we are on a final state
};

static long update_states_cb(void *map, const void *key, void *value, struct loop_ctx *ctx)
{
	struct glob_state *state;
	__s32 k, v = 0;
	long err;

	state = map_lookup_elem(ctx->patternMap, key);
	if (!state) {
		ctx->err = __UINT8_MAX__;
		return 1;
	}

	if (state->hasChar && state->valueChar == ctx->c) {
		k = state->nextChar;
		err = map_update_elem(ctx->nextStatesSet, &k, &v, 0);
		if (err) {
			ctx->err = __UINT8_MAX__;
			return 1;
		}
	}

	if (state->hasQmark) {
		k = state->nextQmark;
		err = map_update_elem(ctx->nextStatesSet, &k, &v, 0);
		if (err) {
			ctx->err = __UINT8_MAX__;
			return 1;
		}
	}

	if (state->hasStar) {
		k = state->nextStar;
		err = map_update_elem(ctx->nextStatesSet, &k, &v, 0);
		if (err) {
			ctx->err = __UINT8_MAX__;
			return 1;
		}

		k = state->idx;
		err = map_update_elem(ctx->nextStatesSet, &k, &v, 0);
		if (err) {
			ctx->err = __UINT8_MAX__;
			return 1;
		}
	}

	return 0;
}

static long count_cb(void *map, const void *key, void *value, void *ctx)
{
	return 0;
}

static long check_final_cb(void *map, const void *key, void *value, struct loop_ctx *ctx)
{
	struct glob_state *state;

	state = map_lookup_elem(ctx->patternMap, key);
	if (!state) {
		ctx->err = __UINT8_MAX__;
		return 1;
	}

	if (state->isFinal) {
		ctx->isFinal = 1;
		return 1;
	}

	return 0;
}

static long cleanup_cb(void *map, const void *key, void *value, void *ctx)
{
	map_delete_elem(map, key);
	return 0;
}

static long loop_cb(u32 index, struct loop_ctx *ctx)
{
	u32 map_id, cpu_id = get_smp_processor_id() * 2;

	if (index >= ctx->len)
		return 1;

	probe_read_kernel(&ctx->c, 1, ctx->path + (index & 255));
	if (!(ctx->c))
		return 1;

	ctx->map_idx = ctx->map_idx ^ 1;
	map_id = ctx->map_idx + cpu_id;
	ctx->nextStatesSet = map_lookup_elem(&glob_temp_maps, &map_id);
	if (!ctx->nextStatesSet) {
		ctx->err = __UINT8_MAX__;
		return 1;
	}

	// iterate currentStates
	for_each_map_elem(ctx->currentStates, &update_states_cb, ctx, 0);
	if (ctx->err) {
		ctx->err = __UINT8_MAX__;
		return 1;
	}

	// here we can cleanup currentStates
	for_each_map_elem(ctx->currentStates, &cleanup_cb, 0, 0);

	ctx->currentStates = ctx->nextStatesSet;

	// if the map of currentStates is empty we will not match anything
	if (for_each_map_elem(ctx->currentStates, &count_cb, 0, 0) == 0)
		return 1;

	return 0;
}

// Returns:
// 1 if the 'path' of size 'len' match on the fsm provided in 'patternMap'
// 0 if the 'path' of size 'len' does not match
// __UINT8_MAX__ in case of error
//
// The type of 'patternMap' should be a map with the following definition:
// struct {
// 	__uint(type, BPF_MAP_TYPE_ARRAY);
// 	__type(key, __u32);
// 	__type(value, struct glob_state);
// 	__uint(max_entries, 256); // number of states in the FSM
// } SEC(".maps");
static u8 check_pattern(void *patternMap, char *path, __u32 len)
{
	struct loop_ctx ctx = {
		.patternMap = patternMap,
		.currentStates = 0,
		.nextStatesSet = 0,
		.map_idx = 0,
		.err = 0,
		.c = 0,
		.path = path,
		.len = len,
		.isFinal = 0,
	};
	s32 zero = 0;
	u32 map_id, cpu_id = get_smp_processor_id() * 2;
	void *map;

	// cleanup temp map 0
	map_id = cpu_id + 0;
	map = map_lookup_elem(&glob_temp_maps, &map_id);
	if (map)
		for_each_map_elem(map, &cleanup_cb, 0, 0);

	// cleanup temp map 1
	map_id = cpu_id + 1;
	map = map_lookup_elem(&glob_temp_maps, &map_id);
	if (map)
		for_each_map_elem(map, &cleanup_cb, 0, 0);

	// get the first temp map
	map_id = ctx.map_idx + cpu_id;
	ctx.currentStates = map_lookup_elem(&glob_temp_maps, &map_id);
	if (!ctx.currentStates)
		return __UINT8_MAX__;

	// add to it the state 0
	ctx.err = map_update_elem(ctx.currentStates, &zero, &zero, 0);
	if (ctx.err < 0)
		return __UINT8_MAX__;

	// iterate through the path
	loop(len, &loop_cb, &ctx, 0);
	if (ctx.err)
		return ctx.err;

	// iterate currentStates and check if any of them has isFinal set
	for_each_map_elem(ctx.currentStates, &check_final_cb, &ctx, 0);
	if (ctx.err)
		return ctx.err;

	return ctx.isFinal;
}

#endif /* __BPF_GLOB_H__ */
