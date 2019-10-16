#ifndef _BPF_EVENTS_H
#define _BPF_EVENTS_H

static inline void event_filename_builder(struct event_execve *event, void *pfilename)
{
	char *filename;

	probe_read(&filename, sizeof(filename), pfilename);
	if (filename)
		probe_read_str(event->filename, sizeof(event->filename), filename);
}

static inline void event_args_builder(struct event_execve *event, void *pargs)
{
	char **args;
	const unsigned int length = ARGSIZE;
	unsigned int offset = 0;

	probe_read(&args, sizeof(args), pargs);
	if (args) {
		unsigned int i = 0;
		bool done = 0;

#pragma clang loop unroll(full)
		for (i = 0; !done && i < 8; i++) {
			char *arg;
			int size = length - offset - 1;

			if (done)
				continue;
			probe_read(&arg, sizeof(arg), &args[i+1]);
			if (!arg) {
				done = 1;
				continue;
			}
			if (size > 0)
				offset += probe_read_str(&event->args[offset&ARGSMASK], size&ARGSSIZEMASK, arg);
		}

		event->args[offset&ARGSMASK] = 0x00;
	}
}

static inline void event_copy_parent(struct msg_ipv4_tcp_connect *dst,
				     struct msg_ipv4_tcp_connect *src)
{
	dst->pid.parent.pid = src->pid.curr.pid;
	dst->pid.parent.uid = src->pid.curr.uid;
	probe_read_str(&dst->pid.parent.filename,
		       sizeof(dst->pid.parent.filename),
		       &src->pid.curr.filename);
	probe_read_str(&dst->pid.parent.args,
		       sizeof(dst->pid.parent.args),
		       &src->pid.curr.args);
}

static inline struct msg_ipv4_tcp_connect *event_find_parent(void)
{
	struct task_struct *task = (struct task_struct *)get_current_task();
	__u32 pid = get_current_pid_tgid() >> 32;
	struct msg_ipv4_tcp_connect *msg = 0;
	char *addr;
	int i;

#pragma unroll
	for (i = 0; i < 4; i++) {
		msg = map_lookup_elem(&execve_map, &pid);
		if (msg && i > 0)
			break;
#ifdef PARENT_OFFSET
		addr = (void *)task;
		addr += PARENT_OFFSET;
#else
		addr = (void *)&(task->parent);
#endif
		probe_read(&task, sizeof(task), addr);
		if (!task)
			break;
#ifdef PARENT_PID_OFFSET
		addr = (void *)(task);
		addr += PARENT_PID_OFFSET;
#else
		addr = (void *)&(task->pid);
#endif
		probe_read(&pid, sizeof(pid), addr);
	}
	return msg;
}

static inline struct msg_ipv4_tcp_connect *event_find_curr(__u32 *ppid)
{
	struct task_struct *task = (struct task_struct *)get_current_task();
	__u32 pid = get_current_pid_tgid() >> 32;
	struct msg_ipv4_tcp_connect *msg = 0;
	char *addr;
	int i;

#pragma unroll
	for (i = 0; i < 4; i++) {
		if (!msg) {
			msg = map_lookup_elem(&execve_map, &pid);
#ifdef PARENT_OFFSET
			addr = (void *)task;
			addr += PARENT_OFFSET;
#else
			addr = (void *)&(task->parent);
#endif
			probe_read(&task, sizeof(task), addr);
			if (!task)
				break;
#ifdef PARENT_PID_OFFSET
			addr = (void *)(task);
			addr += PARENT_PID_OFFSET;
#else
			addr = (void *)&(task->pid);
#endif
			probe_read(&pid, sizeof(pid), addr);
		}
		if (msg)
			break;
	}
	*ppid = pid;
	return msg;
}
#endif // _BPF_EVENTS_H
