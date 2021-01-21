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
#include "types/basic.h"

#define MAX_FILENAME 8096

char _license[] __attribute__((section(("license")), used)) = "GPL";

struct bpf_map_def __attribute__((section("maps"), used)) process_call_heap = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct msg_generic_kprobe),
	.max_entries = 1,
};

__attribute__((section(("kprobe/generic_kprobe")), used))
int generic_kprobe_event(struct pt_regs *ctx)
{
	enum generic_func_args_enum fgs_args;
	int is_syscall, errv, zero = 0;
	struct execve_map_value *enter;
	struct msg_generic_kprobe *e;
	unsigned long a0, a1, a2, a3, a4;
	unsigned long a0m, a1m, a2m, a3m, a4m;
	unsigned long arg_meta;
	struct pt_regs *_ctx;
	__u32 pid;
	/* total is used as a pointer offset so we want type to match
	 * pointer type in order to avoid bit shifts.
	 */
	long ty, total = 0;

	is_syscall = bpf_core_enum_value(fgs_args, syscall);
	if (is_syscall) {
		_ctx = (struct pt_regs *)ctx->di;
		if (!_ctx)
			return 0;
		probe_read(&a0, sizeof(a0), &_ctx->di);
		probe_read(&a1, sizeof(a1), &_ctx->si);
		probe_read(&a2, sizeof(a2), &_ctx->dx);
		probe_read(&a3, sizeof(a3), &_ctx->cx);
		probe_read(&a4, sizeof(a4), &_ctx->r8);
	} else {
		a0 = ctx->di;
		a1 = ctx->si;
		a2 = ctx->dx;
		a3 = ctx->cx;
		a4 = ctx->r8;
	}

	a0m = bpf_core_enum_value(fgs_args, arg0m);
	a1m = bpf_core_enum_value(fgs_args, arg1m);
	a2m = bpf_core_enum_value(fgs_args, arg2m);
	a3m = bpf_core_enum_value(fgs_args, arg3m);
	a4m = bpf_core_enum_value(fgs_args, arg4m);

	pid = get_current_pid_tgid() & 0xFFFFffff;
	e = map_lookup_elem(&process_call_heap, &zero);
	if (!e)
		return 0;

	enter = map_lookup_event(pid);
	if (enter) {
		e->current.pid = pid;
		e->current.ktime = enter->key.ktime;
	} else {
		return 0;
	}

	e->common.op = MSG_OP_GENERIC_KPROBE;
	e->common.flags = 0;
	e->common.pad[0] = 0;
	e->common.pad[1] = 0;
	e->common.size = 0;
	e->common.ktime = ktime_get_ns();

	e->current.pid = pid;
	e->current.pad[0] = 0;
	e->current.pad[1] = 0;
	e->current.pad[2] = 0;
	e->current.pad[3] = 0;

	e->id = bpf_core_enum_value(fgs_args, func_id);

	/* Read out args1-5 */
	ty = bpf_core_enum_value(fgs_args, arg0);
	if (total < 4095) {
		arg_meta = get_arg_meta(a0m, a0, a1, a2, a3, a4);
		errv = read_call_arg(e->args, ty, total, a0, arg_meta, enter);
		if (errv < 0)
			return 0;
		total += errv;
	}

	ty = bpf_core_enum_value(fgs_args, arg1);
	if (total < 4095) {
		arg_meta = get_arg_meta(a1m, a0, a1, a2, a3, a4);
		errv = read_call_arg(e->args, ty, total, a1, arg_meta, enter);
		if (errv < 0)
			return 0;
		total += errv;
	}
	ty = bpf_core_enum_value(fgs_args, arg2);
	if (total < 4095) {
		arg_meta = get_arg_meta(a2m, a0, a1, a2, a3, a4);
		errv = read_call_arg(e->args, ty, total, a2, arg_meta, enter);
		if (errv < 0)
			return 0;
		total += errv;
	}
	ty = bpf_core_enum_value(fgs_args, arg3);
	if (total < 4095) {
		arg_meta = get_arg_meta(a3m, a0, a1, a2, a3, a4);
		errv = read_call_arg(e->args, ty, total, a3, arg_meta, enter);
		if (errv < 0)
			return 0;
		total += errv;
	}
	ty = bpf_core_enum_value(fgs_args, arg4);
	if (total < 4095) {
		arg_meta = get_arg_meta(a4m, a0, a1, a2, a3, a4);
		errv += read_call_arg(e->args, ty, total, a4, arg_meta, enter);
		if (errv < 0)
			return 0;
		total += errv;
	}
	total += sizeof(struct msg_common) + sizeof(struct msg_execve_key) + sizeof(__u64);
	if (total > 8192)
		total = 8192;
	e->common.size = total;
	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, e, total & 0x7fff);
	return 0;
}
