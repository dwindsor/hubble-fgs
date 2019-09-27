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

char _license[] __attribute__((section(("license")), used)) = "GPL";
int  _version __attribute__((section(("version")), used)) = VMLINUX_KERNEL_VERSION;

__attribute__((section(("kprobe/sys_execveat")), used))
int event_execveat(struct pt_regs *__ctx)
{
#ifdef VMLINUX_KERNEL_HAS_SYSCALL_WRAPPER
	struct pt_regs *ctx = (struct pt_regs *) __ctx->di;
#else
	struct pt_regs *ctx = __ctx;
#endif
	struct event_execve event = {0};
	struct task_struct *task;
	char *filename;
	char **args;

	task = (struct task_struct *)get_current_task();

	event.pid = (get_current_pid_tgid() >> 32);
	probe_read(&filename, sizeof(filename), &ctx->si);
	if (!filename)
		return 0;
	probe_read_str(event.filename, sizeof(event.filename), filename);
	probe_read(&args, sizeof(args), &ctx->dx);
	if (args) {
		int i = 0;

		for (i = 0; i < MAXARGS; i++) {
			char *arg = 0;

			probe_read(&arg, sizeof(arg), &args[i+1]);
			if (!arg)
				break;
			probe_read_str(event.args[i], sizeof(event.args[i]), arg);
		}
	}

	map_update_elem(&execve_map, &event.pid, &event, 0);
	return 0;
}
