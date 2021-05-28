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
#include "types/basic.h"

#define MAX_FILENAME 8096

char _license[] __attribute__((section(("license")), used)) = "GPL";

struct bpf_map_def __attribute__((section("maps"), used)) process_call_heap = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct msg_generic_kprobe),
	.max_entries = 1,
};

__attribute__((section(("kprobe/generic_retkprobe")), used))
int generic_kprobe_event(struct pt_regs *ctx)
{
	enum generic_func_args_enum fgs_args;
	struct execve_map_value *enter;
	struct msg_generic_kprobe *e;
	bool walker = false;
	int zero = 0;
	__u64 tid;
	__u32 pid, ppid;
	long total = 0;
	long size, orig_size;
	unsigned long retprobe_buffer;
	long ty;

	e = map_lookup_elem(&process_call_heap, &zero);
	if (!e)
		return 0;

	tid = get_current_pid_tgid();
	pid = tid & 0xFFFFffff;
	e->thread_id = tid;

	ty = bpf_core_enum_value(fgs_args, argreturn);
	retprobe_buffer = retprobe_map_get(tid);
	if (!retprobe_buffer)
		return 0;

	if (ty) {
		size = read_call_arg(e, 0, ty, 0, (unsigned long)ctx->ax, 0, 0);
	} else {
		int *s;

		orig_size = size = (int)ctx->ax;
		size &= 0xfff;
		s = (int *)&e->args[0];
		s[0] = size;
		s[1] = orig_size;
		/* tbd error check and signal to userland */
		probe_read(&e->args[8], size, (char *)retprobe_buffer);
		size +=8;
	}
	/* Complete message header and send */
	enter = event_find_curr(&ppid, 0, &walker);

	e->common.op = MSG_OP_GENERIC_KPROBE;
	e->common.flags = 1;
	e->common.pad[0] = 0;
	e->common.pad[1] = 0;
	e->common.size = size;
	e->common.ktime = ktime_get_ns();

	if (enter) {
		e->current.pid = enter->key.pid;
		e->current.ktime = enter->key.ktime;
	}
	e->current.pad[0] = 0;
	e->current.pad[1] = 0;
	e->current.pad[2] = 0;
	e->current.pad[3] = 0;

	e->id = bpf_core_enum_value(fgs_args, func_id);

	total = size;
	total += generic_kprobe_common_size();
	if (total > 8192)
		total = 8192;
	e->common.size = total;
	asm volatile("%[total] &= 0xfff;\n" : [total] "+r" (total):);
	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, e, total);
	return 0;
}
