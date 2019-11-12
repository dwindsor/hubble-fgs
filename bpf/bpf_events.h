#ifndef _BPF_EVENTS_H
#define _BPF_EVENTS_H

static inline void compiler_barrier(void) {
	asm volatile("" ::: "memory");
}

static inline int64_t validate_arg_size(int64_t size)
{
	compiler_barrier();
	/* Kernels pre 4.15 do not track min values on '&' so we do
	 * the more explicit greather than followed by less than
	 * check to accumulate min/max bounds. Size can not be zero
	 * else older kernels will throw an error on probe_read() we
	 * require a event_execve header regardless so ensure size
	 * accounts for this at minimum.
	 */
	if (size >= BUFFER + offsetof(struct event_execve, args))
		size = BUFFER + offsetof(struct event_execve, args);
	if (size < offsetof(struct event_execve, args))
		size = offsetof(struct event_execve, args);
	compiler_barrier();
	return size;
}

static inline int64_t validate_msg_size(int64_t size)
{
	size_t max = sizeof(struct msg_ipv4_tcp_connect);

	/* validate_msg_size() calls need to happen near caller using the
	 * size. Otherwise, depending on kernel version, the verifier may
	 * lose track of the size bounds. Place a compiler barrier here
	 * otherwise clang will likely place this check near other msg
	 * population calls which can be significant distance away resulting
	 * in losing bounds on older kernels where bounds are not tracked
	 * as rigorously.
	 */
	compiler_barrier();
	if (size > max)
		size = max;
	if (size < 1)
		size = offsetof(struct msg_ipv4_tcp_connect, pid);
	compiler_barrier();
	return size;
}

static inline void event_filename_builder(struct event_execve *pid,
					  __u32 curr_pid, __u32 flags,
					  void *pfilename)
{
	struct event_execve *curr;
	int64_t psize, size = 0;
	char *filename;
	char *earg;

	/* This is a bit parnoid but was previously having trouble on
	 * 4.14 kernels tracking offset of curr through filename_builder
	 * resulting in a a verifier error. We can optimize this a bit
	 * later perhaps and push as an argument.
	 */
	psize = validate_arg_size(pid->size);
	curr = (void *)pid + psize;
	earg = (void *)pid + psize + offsetof(struct event_execve, args);

	probe_read(&filename, sizeof(filename), pfilename);
	if (filename) {
		size = probe_read_str(earg, MAXARGLENGTH - 1, filename);
	}
	if (size == MAXARGLENGTH - 1)
		flags |= EVENT_TRUNC_FILENAME;
	curr->flags = flags;
	curr->pid = curr_pid;
	curr->size = size + offsetof(struct event_execve, args);
}

#define PROBE_ARG_READ(i)	     			\
	"r3 = %[args];"					\
	"r3 += " i ";"		     			\
	"r2 = 8;"		     			\
	"r1 = %[arg];"					\
	"call 4;"					\
	"r1 = %[arg];"					\
	"r3 = *(u64 *)(r1 + 0);"			\
	"if r3 == 0 goto %l[a];"			\
	"r4 = *(u32 *)(%[curr] + 0);"			\
	"if r4 < 0 goto %l[a];"				\
	"if r4 > " XSTR(BUFFER) " goto %l[a];"		\
	"r1 = %[earg];"					\
	"r1 += r4;"					\
	"r2 = " XSTR(MAXARGLENGTH) ";"			\
	"call 45;"					\
	"r4 = *(u32 *)(%[curr] + 0);"			\
	"r0 += r4;"					\
	"*(u32 *)(%[curr] + 0) = r0;"

/* To ensure reading args will work across multiple kernels and pass verifier we
 * code it as an asm block to make it friendly for verifiers. Otherwise, the C
 * code became far too fragile and even small refactors had potential to break
 * some kernel version with whatever set of fixes that kernel has. Not everyone
 * is even using LTS kernels so we get kernels with verifier in strange states.
 * I'm looking at you 4.15 kernel running in minikube!
 */
static inline int probe_arg_read(struct event_execve *c, char *earg, char **args)
{
		volatile char *arg;

		asm volatile goto (
				PROBE_ARG_READ("8")
				PROBE_ARG_READ("16")
				PROBE_ARG_READ("24")
				PROBE_ARG_READ("32")
				PROBE_ARG_READ("40")
			:
			: [earg]         "ri"(earg),
			  [arg]          "ri"(&arg),
			  [args]	 "ri"(args),
			  [curr]	 "ri"(c)
			: "r0", "r1", "r2", "r3", "r4", "r5"
			: a);
a:
	return 0;
}

static inline __u32 __get_auid(struct task_struct *task)
{
	__u32 auid = 0;

	if (!task)
		return auid;

#ifdef AUDIT_STRUCT
	struct audit_task_info *audit;

	probe_read(&audit, sizeof(audit), &task->audit);
	if (audit) {
		probe_read(&auid, sizeof(auid), &audit->loginuid);
	}
#else
	probe_read(&auid, sizeof(auid), &task->loginuid.val);
#endif
	return auid;
}

static inline __u32 get_auid(void)
{
	struct task_struct *task = (struct task_struct *)get_current_task();

	return __get_auid(task);
}

static inline struct task_struct *get_parent(void)
{
	struct task_struct *task = (struct task_struct *)get_current_task();

	probe_read(&task, sizeof(task), &task->parent);
	if (!task)
		return 0;
	return task;
}

static inline __u32 get_parent_auid(void)
{
	struct task_struct *task = get_parent();

	return __get_auid(task);
}

/* event_args_builder: copies args into char *buffer
 * event: pointer to event storage
 * pargs: kernel address of args structure
 *
 * returns: void, because we are using asm_goto here we can't easily
 * also provide return values. To avoid having to try and introspect
 * what happened here this routine should always return with a good
 * event msg that could be passed to userspace.
 */
static inline void event_args_builder(struct msg_ipv4_tcp_connect *event, void *pargs)
{
	struct event_execve *p, *c;
	int64_t base;
	char **args;
	int err;

	probe_read(&args, sizeof(args), pargs);
	if (!args)
		return;

	/* Calculate absolute offset into buffer */
	p = (struct event_execve *)event->pid;
	base = validate_arg_size(p->size);
	c = (struct event_execve *)((void *)p + base);
	c->auid = get_auid();
	c->size += base;
	/* We use flags in asm to indicate overflow */
	compiler_barrier();
	err = probe_arg_read(c, (char*)p, args);
	if (err)
		goto out;
out:
	c->size -= base;
	return;
}

static inline int64_t event_copy_execve(struct event_execve *dst,
					struct event_execve *src)
{
	struct event_execve *esrc;
	int64_t size;

	size = validate_arg_size(src->size);
	esrc = (void*)src + size;
	compiler_barrier();
	size = validate_arg_size(esrc->size);
	compiler_barrier();
	probe_read(dst, size, esrc);
	// must be size (NOT dst->size) because size is sanitized and int64_t
	return size;
}

static inline __u32 event_find_parent_pid(void)
{
	struct task_struct *task = get_parent();
	__u32 pid;

	if (!task)
		return 0;
	probe_read(&pid, sizeof(pid), &task->pid);
	return pid;
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
		if (msg) {
			if (msg->common.size != 0)
				return msg;
		}
	}
	return 0;
}

static inline
struct msg_ipv4_tcp_connect *event_find_curr(__u32 *ppid,bool *walked)
{
	struct task_struct *task = (struct task_struct *)get_current_task();
	__u32 pid = get_current_pid_tgid() >> 32;
	struct msg_ipv4_tcp_connect *msg = 0;
	char *addr;
	int i;

#pragma unroll
	for (i = 0; i < 4; i++) {
		msg = map_lookup_elem(&execve_map, &pid);
		if (!msg)
			break;
		if (msg->common.size != 0)
			break;
		else
			msg = 0;
		*walked = 1;
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
	*ppid = pid;
	return msg;
}


static inline void event_minimal_parent(struct event_execve *event)
{
	__u32 size = offsetof(struct event_execve, args);

	event->size = size;
	event->pid = event_find_parent_pid();
	event->auid = get_parent_auid();
	event->flags = EVENT_MISS;
	event->uid = 0;
}

static inline void event_minimal_curr(struct event_execve *event)
{
	__u32 size = offsetof(struct event_execve, args);

	event->size = size;
	event->pid = (get_current_pid_tgid() >> 32);
	event->auid = get_auid();
	event->flags = EVENT_MISS;
	event->uid = 0;
}

#ifdef USE_HASH_MAP
static inline void map_update_hash(struct msg_ipv4_tcp_connect *event,
				   __u32 pid)
{
	struct event_execve *parent = (struct event_execve *)event->pid;
	struct event_execve *curr;
	uint64_t size;

	curr = (void *)parent + validate_arg_size(parent->size);
	size = offsetof(struct msg_ipv4_tcp_connect, pid) + parent->size + curr->size;
	size = validate_msg_size(size);
	map_update_elem(&execve_map, &pid, event, 0);
}

static inline struct msg_ipv4_tcp_connect *map_lookup_event(__u32 pid)
{
	struct msg_ipv4_tcp_connect *event;

	event = map_lookup_elem(&execve_map, &pid);
	if (!event) {
		int zero = 0;

		event = map_lookup_elem(&msg_ipv4_tcp_map, &zero);
		if (!event)
			return 0;
	}
	return event;
}
#else
static inline void map_update_hash(struct msg_ipv4_tcp_connect *event,
				   __u32 pid)
{
}

static inline struct msg_ipv4_tcp_connect *map_lookup_event(__u32 pid)
{
	return map_lookup_elem(&execve_map, &pid);
}
#endif
#endif // _BPF_EVENTS_H
