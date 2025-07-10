#ifndef __BPF_GLOB_H__
#define __BPF_GLOB_H__

#include "vmlinux.h"
#include "api.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"

// the maximum number of possible next states for each character in that inpput path
#define POSSIBLE_MAX_STATES	 512 // this should match GlobPossibleMaxStates in pkg/sensors/file/utils/glob.go
#define POSSIBLE_MAX_STATES_MASK (POSSIBLE_MAX_STATES - 1)

#define BITMAP_SHIFT  6
#define BITMAP_MASK   63
#define BITS_PER_BYTE 8

/*
 * The following struct represents a set of states (each state is represented
 * as a number). The operations that we should support (and be efficient) are
 * to add states, to iterate those, and to cleanup the whole set. In order to
 * make that efficient we use a set of arrays where each of those is used for
 * a different purpose.
 *
 * 1. Adding elements:
 *    Adding an element needs two steps. First we use s->v to check if the
 *    element already exists. s->v is an array of bytes where each position
 *    shows if the corresponding state is in the set. i.e. if s->v is 1
 *    this means that the state '5' is in the set. If we want to add an element
 *    and this does not exist, we make the corresponding position 1 and we append
 *    that value to s->values. This is an append only array that will be used
 *    later to make iteration faster.
 *
 * 2. Bulk delete:
 *    We use memset to zero s->v. There is no need to zero out the append-only
 *    array.
 *
 * 3. Iteration:
 *    We use s->values from index 0 to (s->cnt - 1). This does require to check
 *    if an element exists or not and this makes iteration much faster compared
 *    to the need to iterate s->e.v8 and check if each element is 1 or 0.
 *
 * Limitations:
 *    We require that each FSM produced in the user space not to have more than
 *    POSSIBLE_MAX_STATES (512) states. There is a check in the user-space when
 *    we generate selectors for FIM and if a pattern inside a tracing policy results
 *    in more than that, we reject the tracing policy. As an example, the largest
 *    number of states from those https://github.com/isovalent/hubble-fgs/blob/e2ae12f551b36cbf2a4996cf977787e7d14620b7/pkg/sensors/file/utils/glob_test_cases.go#L20-L61
 *    patterns is 34. So 512 should be enough for almost all (reasonable) cases.
 */
struct __attribute__((aligned(8))) glob_temp_val {
	__u64 v[POSSIBLE_MAX_STATES / BITS_PER_BYTE / sizeof(uint64_t) /* one bit per state */];
	__u32 values[POSSIBLE_MAX_STATES];
	__u64 cnt;
};

static inline __attribute__((always_inline)) void bitmap_set(struct glob_temp_val *b, int n)
{
	int word = n >> BITMAP_SHIFT;
	int position = n & BITMAP_MASK;
	b->v[word] |= (uint64_t)1 << position;
}

static inline __attribute__((always_inline)) int bitmap_read(struct glob_temp_val *b, int n)
{
	int word = n >> BITMAP_SHIFT;
	int position = n & BITMAP_MASK;
	return (b->v[word] >> position) & 1;
}

static void add_elem_glob_temp_val(struct glob_temp_val *m, u32 key)
{
	// to make the verifier happy
	asm volatile("%[key] &= %1;\n"
		     : [key] "+r"(key)
		     : "i"(POSSIBLE_MAX_STATES_MASK));

	if (bitmap_read(m, key) == 0) { // if the key does not exist
		m->values[m->cnt & POSSIBLE_MAX_STATES_MASK] = key; // append that to the array
		bitmap_set(m, key); // set this to the "bytemap"
		m->cnt++; // increase the number of elements
	}
	// nothing to do if the element already exists
}

static void cleanup_glob_temp_val(struct glob_temp_val *m)
{
	memset(m->v, 0, sizeof(m->v));
	m->cnt = 0;
	// no need to zero out the append-only array
	// as we get elements from index 0 to m->cnt
}

struct __for_each_ctx {
	struct glob_temp_val *m;
	struct loop_ctx *callback_ctx;
};

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
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1); // user set this
	__type(key, __u32);
	__type(value, struct glob_temp_val);
} glob_temp_maps SEC(".maps");

struct loop_ctx {
	struct glob_temp_val *currentStates; // current set of states
	struct glob_temp_val *nextStatesSet; // next set of states
	void *patternMap; // the map that contains the states of the FSM
	u32 map_idx; // the id of the map to use in the current iteration (0 or 1)
	char *path; // the path to match
	u32 len; // the len of the path to match
	u8 err; // != 0 in case of errors
	u8 c; // teh current character of the path
	u8 isFinal; // 1 if we are on a final state
};

static long update_states_cb(u64 index, struct __for_each_ctx *_ctx)
{
	struct loop_ctx *ctx = _ctx->callback_ctx;
	struct glob_temp_val *m = _ctx->m;
	struct glob_state *state;
	u32 k;

	// to make the verifier happy
	asm volatile("%[index] &= %1;\n"
		     : [index] "+r"(index)
		     : "i"(POSSIBLE_MAX_STATES_MASK));

	k = m->values[index];
	state = map_lookup_elem(ctx->patternMap, &k);
	if (!state) {
		ctx->err = __UINT8_MAX__;
		return 1;
	}

	if (state->hasChar && state->valueChar == ctx->c) {
		k = state->nextChar;
		add_elem_glob_temp_val(ctx->nextStatesSet, k);
	}

	if (state->hasQmark) {
		k = state->nextQmark;
		add_elem_glob_temp_val(ctx->nextStatesSet, k);
	}

	if (state->hasStar) {
		k = state->nextStar;
		add_elem_glob_temp_val(ctx->nextStatesSet, k);

		k = state->idx;
		add_elem_glob_temp_val(ctx->nextStatesSet, k);
	}

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
	loop(ctx->currentStates->cnt, &update_states_cb, &(struct __for_each_ctx){ .m = ctx->currentStates, .callback_ctx = ctx }, 0);
	if (ctx->err) {
		ctx->err = __UINT8_MAX__;
		return 1;
	}

	// here we can cleanup currentStates
	cleanup_glob_temp_val(ctx->currentStates);

	ctx->currentStates = ctx->nextStatesSet;

	// if the map of currentStates is empty we will not match anything
	if (ctx->currentStates->cnt == 0)
		return 1;

	return 0;
}

static long check_final_cb(u64 index, struct __for_each_ctx *_ctx)
{
	struct loop_ctx *ctx = _ctx->callback_ctx;
	struct glob_temp_val *m = _ctx->m;
	struct glob_state *state;
	u32 k;

	// to make the verifier happy
	asm volatile("%[index] &= %1;\n"
		     : [index] "+r"(index)
		     : "i"(POSSIBLE_MAX_STATES_MASK));

	k = m->values[index];
	state = map_lookup_elem(ctx->patternMap, &k);
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
	u32 map_id, cpu_id = get_smp_processor_id() * 2;
	void *map;

	// cleanup temp map 0
	map_id = cpu_id + 0;
	map = map_lookup_elem(&glob_temp_maps, &map_id);
	if (map)
		cleanup_glob_temp_val(map);

	// cleanup temp map 1
	map_id = cpu_id + 1;
	map = map_lookup_elem(&glob_temp_maps, &map_id);
	if (map)
		cleanup_glob_temp_val(map);

	// get the first temp map
	map_id = ctx.map_idx + cpu_id;
	ctx.currentStates = map_lookup_elem(&glob_temp_maps, &map_id);
	if (!ctx.currentStates)
		return __UINT8_MAX__;

	// add to it the state 0
	add_elem_glob_temp_val(ctx.currentStates, 0);

	// iterate through the path
	loop(len, &loop_cb, &ctx, 0);
	if (ctx.err)
		return ctx.err;

	// iterate currentStates and check if any of them has isFinal set
	loop(ctx.currentStates->cnt, &check_final_cb, &(struct __for_each_ctx){ .m = ctx.currentStates, .callback_ctx = &ctx }, 0);
	if (ctx.err)
		return ctx.err;

	return ctx.isFinal;
}

#endif /* __BPF_GLOB_H__ */
