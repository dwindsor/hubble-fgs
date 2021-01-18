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
	int is_syscall, ty, errv, zero = 0;
	struct execve_map_value *enter;
	struct msg_generic_kprobe *e;
	unsigned long a0, a1, a2, a3, a4;
	struct pt_regs *_ctx;
	__u32 pid;
	/* total is used as a pointer offset so we want type to match
	 * pointer type in order to avoid bit shifts.
	 */
	long total = 0;

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

	pid = get_current_pid_tgid() & 0xFFFFffff;
	e = map_lookup_elem(&process_call_heap, &zero);
	if (!e)
		return 0;

	enter = map_lookup_event(pid);
	if (enter) {
		e->current.pid = pid;
		e->current.ktime = enter->key.ktime;
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
	if (ty >= 0 && ty + total < 4095) {
		errv = read_call_arg(e->args, ty, total, a0);
		if (errv >= 0)
			total+=errv;
	}

	ty = bpf_core_enum_value(fgs_args, arg1);
	if (ty >= 0 && ty + total < 4095) {
		errv += read_call_arg(e->args, ty, total, a1);
		if (errv >= 0)
			total+=errv;
	}
	ty = bpf_core_enum_value(fgs_args, arg2);
	if (ty >= 0 && ty + total < 4095) {
		errv += read_call_arg(e->args, ty, total, a2);
		if (errv >= 0)
			total+=errv;
	}
	ty = bpf_core_enum_value(fgs_args, arg3);
	if (ty >= 0 && ty + total < 4095) {
		errv += read_call_arg(e->args, ty, total, a3);
		if (errv >= 0)
			total+=errv;
	}
	ty = bpf_core_enum_value(fgs_args, arg4);
	if (ty >= 0 && ty + total < 4095) {
		errv += read_call_arg(e->args, ty, total, a4);
		if (errv >= 0)
			total+=errv;
	}

	total += sizeof(struct msg_common) + sizeof(struct msg_execve_key) + sizeof(__u64);
	if (total > 8192)
		total = 8192;
	e->common.size = total;
	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, e, total&0xfff);
	return 0;
}
