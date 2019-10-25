#ifndef _BPF_EVENTS_H
#define _BPF_EVENTS_H

static inline unsigned int validate_arg_size(int size)
{
	size &= ARGSSIZEMASK;
	if (size < 0)
		size = 0;
	return size;
}

static inline void validate_msg_size(struct msg_ipv4_tcp_connect *msg)
{
	if (msg->common.size > sizeof(*msg))
		msg->common.size = sizeof(*msg);
}

static inline unsigned int event_filename_builder(struct event_execve *event, void *pfilename)
{
	char *earg = (void*)event + offsetof(struct event_execve, args);
	unsigned int size = ARGSIZE;
	char *filename;

	probe_read(&filename, sizeof(filename), pfilename);
	if (filename) {
		size = probe_read_str(earg, size, filename);
	} else {
		size = 0;
	}
	return size;
}

static inline int event_args_builder(struct event_execve *event, unsigned int offset, void *pargs)
{
	char *earg = (void*)event + offsetof(struct event_execve, args);
	const unsigned int length = ARGSIZE;
	char **args;

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
				offset += probe_read_str(&earg[offset&ARGSMASK], size&ARGSSIZEMASK, arg);
		}
	}
	event->size = offset;
	return event->size;
}

static inline int event_copy_execve(struct event_execve *dst,
				    struct event_execve *src)
{
	char *edst = (void*)dst + offsetof(struct event_execve, args);
	char *esrc;
	int size = src->size;

	size &= ARGSSIZEMASK;
	if (size < 0)
		size = 0;
	src = (void*)src + size;
	esrc = (void*)src + offsetof(struct event_execve, args);

	dst->size = src->size;
	dst->pid = src->pid;
	dst->uid = src->uid;
	size = validate_arg_size(dst->size);
	probe_read(edst, size, esrc);
	return dst->size;
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

		msg = map_lookup_elem(&execve_map, &pid);
		if (msg)
			break;
	}
	return msg;
}

static inline struct msg_ipv4_tcp_connect *event_find_curr(__u32 *ppid)
{
	struct task_struct *task = (struct task_struct *)get_current_task();
	__u32 cpid, pid = get_current_pid_tgid() >> 32;
	struct msg_ipv4_tcp_connect *msg = 0;
	char *addr;
	int i;

	cpid = pid;
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
