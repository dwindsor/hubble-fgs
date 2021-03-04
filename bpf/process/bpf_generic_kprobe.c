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
	.max_entries	= 2,
};


/* Arrays of size 1 will be rewritten to direct loads in verifier */
struct bpf_map_def __attribute__((section("maps"), used)) args0_filter_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = 80,
	.max_entries = 1,
};

struct bpf_map_def __attribute__((section("maps"), used)) args1_filter_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = 80,
	.max_entries = 1,
};

struct bpf_map_def __attribute__((section("maps"), used)) args2_filter_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = 80,
	.max_entries = 1,
};

struct bpf_map_def __attribute__((section("maps"), used)) args3_filter_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = 80,
	.max_entries = 1,
};

struct bpf_map_def __attribute__((section("maps"), used)) args4_filter_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = 80,
	.max_entries = 1,
};

static inline __attribute__((always_inline))
int generic_kprobe_process_filter(struct pt_regs *ctx)
{
	int ret, is_syscall, zero = 0;
	struct msg_generic_kprobe *msg;
	enum generic_func_args_enum fgs_args;

	msg = map_lookup_elem(&process_call_heap, &zero);
	if (!msg)
		return 0;

	ret = generic_process_filter(&msg->current);
	if (ret != PFILTER_PASSED)
		return 0;

	is_syscall = bpf_core_enum_value(fgs_args, syscall);
	if (is_syscall) {
		struct pt_regs *_ctx;
		_ctx = (struct pt_regs *)ctx->di;
		if (!_ctx)
			return 0;
		probe_read(&msg->a0, sizeof(msg->a0), &_ctx->di);
		probe_read(&msg->a1, sizeof(msg->a1), &_ctx->si);
		probe_read(&msg->a2, sizeof(msg->a2), &_ctx->dx);
		probe_read(&msg->a3, sizeof(msg->a3), &_ctx->cx);
		probe_read(&msg->a4, sizeof(msg->a4), &_ctx->r8);
	} else {
		msg->a0 = ctx->di;
		msg->a1 = ctx->si;
		msg->a2 = ctx->dx;
		msg->a3 = ctx->cx;
		msg->a4 = ctx->r8;
	}
	msg->common.op = MSG_OP_GENERIC_KPROBE;

	tail_call(ctx, &kprobe_calls, 0);
	return 0;
}

/* Generic kprobe is composed of two parts, first we filter process with
 * process filters (nspid, pid, etc.) then if we accpet the process we
 * run the arg filters and event builder. For 4.19 kernels we have to
 * use the tail call infrastructure to get below 4k insns. For 5.x+ kernels
 * with 1m.insns its not an issue.
 */
__attribute__((section(("kprobe/generic_kprobe")), used))
int generic_kprobe_event(struct pt_regs *ctx)
{
	return generic_kprobe_process_filter(ctx);
}

__attribute__((section(("kprobe/0")), used))
int generic_kprobe_process_event0(void *ctx)
{
	return generic_process_event0(
		ctx,
		&process_call_heap,
		&args0_filter_map,
		&args1_filter_map,
		&args2_filter_map,
		&kprobe_calls);
}
__attribute__((section(("kprobe/1")), used))
int generic_kprobe_process_event1(void *ctx)
{
	return generic_process_event1(
		ctx,
		&process_call_heap,
		&args3_filter_map,
		&args4_filter_map);
}

