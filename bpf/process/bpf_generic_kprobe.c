#include "vmlinux.h"
#include "api.h"

#ifndef bpf_map_def
struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};
#endif

#include "hubble_msg.h"
#include "bpf_events.h"
#include "retprobe_map.h"
#include "types/operations.h"
#include "types/basic.h"
#include "generic_calls.h"
#include "pfilter.h"

char _license[] __attribute__((section(("license")), used)) = "GPL";

struct bpf_map_def __attribute__((section("maps"), used)) process_call_heap = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct msg_generic_kprobe),
	.max_entries = 1,
};

struct bpf_map_def __attribute__((section("maps"), used)) kprobe_calls = {
	.type		= BPF_MAP_TYPE_PROG_ARRAY,
	.key_size	= sizeof(__u32),
	.value_size	= sizeof(__u32),
	.max_entries	= 6,
};

/* Arrays of size 1 will be rewritten to direct loads in verifier */
struct bpf_map_def __attribute__((section("maps"), used)) filter_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = 4096,
	.max_entries = 1,
};

static inline __attribute__((always_inline))
int generic_kprobe_process_filter(struct pt_regs *ctx)
{
	int ret, zero = 0;
	struct msg_generic_kprobe *msg;

	msg = map_lookup_elem(&process_call_heap, &zero);
	if (!msg)
		return 0;

	ret = generic_process_filter(msg, &filter_map);
	if (ret != PFILTER_PASSED)
		return 0;

	tail_call(ctx, &kprobe_calls, 0);
	return 0;
}

/* Generic kprobe pseudocode is the following
 *
 *  filter_pids -> drop if no matches
 *  copy arguments buffer
 *  filter selectors -> drop if no matches
 *  generate ring buffer event
 *
 * First we filter by pids this allows us to quickly job events
 * that are not relevant. This is helpful if we end up copying
 * large string values.
 *
 * Then we copy arguments then run full selectors logic. We keep
 * track of pids that passed initial filter so we avoid running
 * pid filters twice.
 *
 * For 4.19 kernels we have to use the tail call infrastructure
 * to get below 4k insns. For 5.x+ kernels with 1m.insns its not
 * an issue.
 */
__attribute__((section(("kprobe/generic_kprobe")), used))
int generic_kprobe_event(struct pt_regs *ctx)
{
	return generic_kprobe_process_filter(ctx);
}

__attribute__((section(("kprobe/0")), used))
int generic_kprobe_process_event0(void *ctx)
{
	return generic_process_event_and_setup(
		ctx,
		&process_call_heap,
		&filter_map,
		&kprobe_calls);
}

__attribute__((section(("kprobe/1")), used))
int generic_kprobe_process_event1(void *ctx)
{
	return generic_process_event1(
		ctx,
		&process_call_heap,
		&filter_map,
		&kprobe_calls);
}

__attribute__((section(("kprobe/2")), used))
int generic_kprobe_process_event2(void *ctx)
{
	return generic_process_event2(
		ctx,
		&process_call_heap,
		&filter_map,
		&kprobe_calls);
}

__attribute__((section(("kprobe/3")), used))
int generic_kprobe_process_event3(void *ctx)
{
	return generic_process_event3(
		ctx,
		&process_call_heap,
		&filter_map,
		&kprobe_calls);
}

__attribute__((section(("kprobe/4")), used))
int generic_kprobe_process_event4(void *ctx)
{
	return generic_process_event4(
		ctx,
		&process_call_heap,
		&filter_map);
}
