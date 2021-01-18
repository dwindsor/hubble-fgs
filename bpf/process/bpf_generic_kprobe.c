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
#define MAX_STRING 1024 

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
	struct msg_generic_kprobe *e;
	struct execve_map_value *enter;
	int ty, errv, total = 0, zero = 0;
	enum generic_func_args_enum fgs_args;
	__u32 pid;

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
		errv = read_call_arg(e->args, ty, total, (void *)ctx->di);
		if (errv >= 0)
			total+=errv;
	}

	ty = bpf_core_enum_value(fgs_args, arg1);
	if (ty >= 0 && ty + total < 4095) {
		errv += read_call_arg(e->args, ty, total, (void *)ctx->si);
		if (errv >= 0)
			total+=errv;
	}
	ty = bpf_core_enum_value(fgs_args, arg2);
	if (ty >= 0 && ty + total < 4095) {
		errv += read_call_arg(e->args, ty, total, &ctx->dx);
		if (errv >= 0)
			total+=errv;
	}
	ty = bpf_core_enum_value(fgs_args, arg3);
	if (ty >= 0 && ty + total < 4095) {
		errv += read_call_arg(e->args, ty, total, &ctx->cx);
		if (errv >= 0)
			total+=errv;
	}
	ty = bpf_core_enum_value(fgs_args, arg4);
	if (ty >= 0 && ty + total < 4095) {
		errv += read_call_arg(e->args, ty, total, &ctx->r8);
		if (errv >= 0)
			total+=errv;
	}

	total += sizeof(struct msg_common) + sizeof(struct msg_execve_key) + sizeof(__u64);
	if (total > 8192) {
		bpf_printk("ETOOLARGE? %d\n", total);
		total = 8192;
	}
	e->common.size = total;
	bpf_printk("post event %d\n", total);
	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, e, total&0xfff);
	return 0;
}
