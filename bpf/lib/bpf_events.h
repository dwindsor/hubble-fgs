#ifndef _BPF_EVENTS_H
#define _BPF_EVENTS_H

#define _(P) (__builtin_preserve_access_index(P))

/* second argument to __builtin_preserve_enum_value() built-in */
enum bpf_enum_value_kind {
	BPF_ENUMVAL_EXISTS = 0,		/* enum value existence in kernel */
	BPF_ENUMVAL_VALUE = 1,		/* enum value value relocation */
};

/*
 * Convenience macro to get the integer value of an enumerator value in
 * a target kernel.
 * Returns:
 *    64-bit value, if specified enum type and its enumerator value are
 *    present in target kernel's BTF;
 *    0, if no matching enum and/or enum value within that enum is found.
 */
#define bpf_core_enum_value(enum_type, enum_value)			    \
	__builtin_preserve_enum_value(*(typeof(enum_type) *)enum_value, BPF_ENUMVAL_VALUE)

#include "bpf_core_read.h"

static inline void compiler_barrier(void) {
	asm volatile("" ::: "memory");
}

static inline __attribute__((always_inline))
int64_t validate_arg_size(int64_t size)
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

static inline __attribute__((always_inline))
int64_t validate_msg_execve_size(int64_t size)
{
	size_t max = sizeof(struct msg_execve_event);

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
		size = offsetof(struct msg_execve_event, pid);
	compiler_barrier();
	return size;
}

static inline __attribute__((always_inline))
struct execve_map_value *map_lookup_hash(__u32 pid)
{
	struct execve_map_value *event;

	event = map_lookup_elem(&execve_map, &pid);
	if (!event) {
		struct execve_map_value value;
		int err, zero = 0;
		__s64 *cntr;

		memset(&value, 0, sizeof(struct execve_map_value));
		err = map_update_elem(&execve_map, &pid, &value, 0);
		if (!err && (cntr = map_lookup_elem(&execve_map_stats, &zero)))
			*cntr = *cntr + 1;
		event = map_lookup_elem(&execve_map, &pid);
	}
	return event;
}

static inline __attribute__((always_inline))
struct execve_map_value *map_lookup_array(__u32 pid)
{
	return map_lookup_elem(&execve_map, &pid);
}

static inline __attribute__((always_inline))
struct execve_map_value *map_lookup_event(__u32 pid)
{
	return map_lookup_hash(pid);
}

static inline __attribute__((always_inline))
void map_delete_array(__u32 pid)
{
	struct execve_map_value *v = map_lookup_array(pid);

	if (v)
		v->flags = 0; // deleting array element is zero flags
}

static inline __attribute__((always_inline))
void map_delete_hash(__u32 pid)
{
	int err = map_delete_elem(&execve_map, &pid);
	int zero = 0;
	__s64 *cntr;

	if (!err && (cntr = map_lookup_elem(&execve_map_stats, &zero)))
		*cntr = *cntr - 1;
}

static inline __attribute__((always_inline))
void map_delete_event(__u32 pid)
{
	map_delete_hash(pid);
}

static inline __attribute__((always_inline))
__u64 __get_auid(struct task_struct *task)
{
	// u64 to convince compiler to do 64bit loads early kernels do not
	// support 32bit loads from stack, e.g. r1 = *(u32 *)(r10 -8).
	__u64 auid = 0;

	if (!task)
		return auid;

	if (bpf_core_field_exists(task->loginuid)) {
		probe_read(&auid, sizeof(auid), _(&task->loginuid.val));
	} else {
		struct audit_task_info *audit;

		if (bpf_core_field_exists(task->audit)) {
			probe_read(&audit, sizeof(audit), _(&task->audit));
			if (audit) {
				probe_read(&auid, sizeof(__u32), _(&audit->loginuid));
			}
		}
	}

	return auid;
}

static inline __attribute__((always_inline))
__u32 get_auid(void)
{
	struct task_struct *task = (struct task_struct *)get_current_task();

	return __get_auid(task);
}

static inline __attribute__((always_inline))
struct task_struct *get_parent(struct task_struct *t)
{
	struct task_struct *task;

	probe_read(&task, sizeof(task), _(&t->parent));
	if (!task)
		return 0;
	return task;
}

static inline __attribute__((always_inline))
__u64 get_parent_auid(struct task_struct *t)
{
	struct task_struct *task = get_parent(t);

	return __get_auid(task);
}

static inline __attribute__((always_inline))
struct task_struct *get_task_from_pid(__u32 pid)
{
	struct task_struct *task = (struct task_struct *)get_current_task();
	__u32 cpid = 0;
	int i;

#define TASK_PID_LOOP 20
#pragma unroll
	for (i = 0; i < TASK_PID_LOOP; i++) {
		if (!task) {
			i = TASK_PID_LOOP;
			continue;
		}
		probe_read(&cpid, sizeof(cpid), _(&task->tgid));
		if (cpid == pid) {
			i = TASK_PID_LOOP;
			continue;
		}
		task = get_parent(task);
	}
	if (cpid != pid)
		return 0;
	return task;
}

#define CWD_DENTRY_REG "r9"
#define CWD_VFSMNT_DENTRY_REG "r6"
#define CWD_OFFSET_REG "r7"

#define PROBE_CWD_READ_LOOP_HEADER				\
	CWD_DENTRY_REG " = *(u64 *)%[dentry];\n"		\
	CWD_VFSMNT_DENTRY_REG " = *(u64 *)%[vfsmnt];\n"		\
	CWD_OFFSET_REG " = *(u32 *)%[offset];\n"

#define PROBE_CWD_READ	  	   			\
	/* if (!dentry) { break; } */			\
	"r3 = " CWD_DENTRY_REG ";\n"			\
	"if r3 == 0 goto %l[a];\n"			\
	/* probe_read(&parent, sizeof(parent), &dentry->d_parent); */ \
	"r2 = *(u32 *)%[dentry_parent];\n"		\
	"r3 += r2;\n"					\
	"r2 = 8;\n"					\
	"r1 = %[ptr];\n"				\
	"call 4;\n"					\
	/* if (!parent) { break; } */			\
	"r4 = *(u64 *)(%[ptr] + 0);\n"			\
	"if r4 == 0x0 goto %l[a];\n"			\
	/* if (vfsmnt_dentry && dentry == vfsmnt_dentry) { */ \
	"if " CWD_VFSMNT_DENTRY_REG " == " CWD_DENTRY_REG " goto %l[a];\n" \
	/* name = &dentry->d_name; */			\
	/* dentry = parent; */				\
	/* probe_read(&dname, sizeof(dname), &name->name); */ \
	"r3 = " CWD_DENTRY_REG ";\n"			\
	"r2 = *(u32 *)%[dentry_name];\n"		\
	"r3 += r2;\n"					\
	CWD_DENTRY_REG " = r4;\n" /* r9 = parent */	\
	"r1 = %[ptr];\n"				\
	"r2 = 8;\n"					\
	"call 4;\n"					\
	/* pcwd = curr + offset */			\
	/* probe_read(pcwd, 1, &slash); */		\
	"r1 = *(u64 *)%[pid];\n"			\
	"if " CWD_OFFSET_REG " s< 0 goto %l[a];\n"	\
	"if " CWD_OFFSET_REG " s> 1188 goto %l[a];\n"	\
	"r1 += " CWD_OFFSET_REG ";\n"			\
	"r2 = 1;\n"					\
	"r3 = *(u64 *)%[slash];\n"			\
	"call 4;\n"					\
	/* pcwd++; */					\
	/* ret = probe_read_str(pcwd, CWD_MAX, dname); */ \
	CWD_OFFSET_REG " += 1;\n"			\
	"r1 = *(u64 *)%[pid];\n"			\
	"if " CWD_OFFSET_REG " < 0 goto %l[a];\n"	\
	"if " CWD_OFFSET_REG " > 1188 goto %l[a];\n"	\
	"r1 += " CWD_OFFSET_REG ";\n"			\
	"r2 = " XSTR(CWD_MAX) ";\n"			\
	"r3 = *(u64 *)(%[ptr] + 0);\n"			\
	"call 45;\n"					\
	/* if (ret < 0) { */				\
	/* cwdsize += ret */				\
	"if r0 s< 1 goto %l[a];\n"			\
	"r0 -= 1\n;"					\
	CWD_OFFSET_REG " += r0;\n"			\
	"*(u32 *)%[offset] = " CWD_OFFSET_REG ";\n"

#define offsetof_btf(s, memb) \
	((size_t)((char *)_(&((s *)0)->memb) - (char *)0))

static inline __attribute__((always_inline))
long getpath(void *curr, struct path path, volatile long offset)
{
	struct dentry *dentry, *vfsmnt_dentry;
	long dentry_parent, dentry_name;
	struct vfsmount *vfsmnt;
	char slash, *pslash;
	long *ptr = 0;

	/* Verify complains if this is not a constant (compiler optimizes
	 * us into a corner ottherwise). So for now note qstr->name is 8
	 * bytes into struct on all kernels we use.
	 */
	const int qstr = 8;

	slash = '/';
	pslash = &slash;

	dentry = path.dentry;
	vfsmnt = path.mnt;
	probe_read(&vfsmnt_dentry, sizeof(vfsmnt_dentry), _(&vfsmnt->mnt_root));

	dentry_parent = offsetof_btf(struct dentry, d_parent);
	dentry_name = offsetof_btf(struct dentry, d_name);
	dentry_name += qstr;

	/* For 'asm goto' offset needs to be a memory address otherwise
	 * code may load the value from memory into a register in the preheader,
	 * but then goto logic will not know to load final result back into
	 * memory on goto exit. The result is some code like this,
	 *
	 * call 45
	 * if r0 s< 1 goto +42 <LBB0_77>
	 * r0 -= 1
	 * r7 += r0
	 * *(u64 *)(r10 - 168) = r7
	 *
	 * Notice we skip the load at the end needed to push offset back into
	 * stack. Later we might have code like this,
	 *
	 * r3 = *(u64 *)(r10 - 168)
	 *
	 * That expect to load the new offset, but its not there. To make
	 * things extra convoluted we are short on registers so can't mark
	 * offset as clobbered. In order to defeat compiler though we mark
	 * offset volatile above and this forces the retrun __offset to reload
	 * the value from stack.
	 */
	asm volatile goto (
			PROBE_CWD_READ_LOOP_HEADER
			PROBE_CWD_READ
			PROBE_CWD_READ
			PROBE_CWD_READ
			PROBE_CWD_READ
			PROBE_CWD_READ
			PROBE_CWD_READ
			PROBE_CWD_READ
			PROBE_CWD_READ
			PROBE_CWD_READ
			PROBE_CWD_READ
			PROBE_CWD_READ
			PROBE_CWD_READ
			PROBE_CWD_READ
			PROBE_CWD_READ
			PROBE_CWD_READ
		:
		: [pid]    "m"(curr),
		  [vfsmnt] "m"(vfsmnt_dentry),
		  [dentry] "m"(dentry),
		  [ptr]    "+r"(&ptr),
		  [slash]  "m"(pslash),
		  [dentry_parent] "m"(dentry_parent),
		  [dentry_name] "m"(dentry_name),
		  [offset] "+m"(offset)
		: "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r9", "memory"
		: a);
a:
	return offset;
}

static inline __attribute__((always_inline))
int64_t getcwd(struct event_execve *curr,
	       __u32 offset, __u32 proc_pid, bool prealloc)
{
	struct task_struct *task = get_task_from_pid(proc_pid);
	__u32 orig_size = curr->size, orig_offset = offset;
	struct fs_struct *fs;
	struct path pwd;

	probe_read(&fs, sizeof(fs), _(&task->fs));
	if (!fs) {
		curr->flags |= EVENT_ERROR_CWD;
		return 0;
	}

	probe_read(&pwd, sizeof(pwd), _(&fs->pwd));
	offset = getpath(curr, pwd, offset);
	curr->size = offset;
	// Unfortunate special case for '/' where nothing was added we need
	// to truncate with '\n' for parser.
	if (curr->size == orig_offset)
		curr->flags |= EVENT_ROOT_CWD;

	/* If the size was preallocated from user space side (ProcFS entry)
	 * then we need to keep the same size so we can find parent/child
	 * entries.
	 */
	if (prealloc)
		curr->size = orig_size;
	return 0;
}

static inline __attribute__((always_inline))
__u32 get_task_pid_vnr(void)
{
	struct task_struct *task = (struct task_struct *)get_current_task();
	int thread_pid_exists;
	unsigned int level;
	struct upid upid;
	struct pid *pid;
	int upid_sz;

	thread_pid_exists = bpf_core_field_exists(task->thread_pid);
	if (thread_pid_exists) {
		probe_read(&pid, sizeof(pid), _(&task->thread_pid));
		if (!pid) {
			return 0;
		}
	} else {
		struct pid_link link;
		int link_sz = bpf_core_field_size(task->pids);

		/* 4.14 verifier did not prune this branch even though we
		 * have the if (0) above after BTF exists check. So it will
		 * try to run this probe_read and throw an error. So lets
		 * sanitize it for the verifier.
		 */
		if (!thread_pid_exists)
			link_sz = 24; // voodoo magic, hard-code 24 to init stack
		probe_read(&link, link_sz, (void *)_(&task->pids) + (PIDTYPE_PID * link_sz));
		pid = link.pid;
	}
	upid_sz = bpf_core_field_size(pid->numbers[0]);
	probe_read(&level, sizeof(level), _(&pid->level));
	if (level < 1)
		return 0;
	probe_read(&upid, upid_sz, (void *)_(&pid->numbers) + (level * upid_sz));
	return upid.nr;
}

static inline __attribute__((always_inline))
uint32_t event_filename_builder(struct event_execve *curr,
				__u32 curr_pid, __u32 flags,
				void *filename)
{
	int64_t size = 0;
	uint32_t *value;
	char *earg;

	/* For now we set pathname on stack with zero initializer because its
	 * easy. We should push this into a map or do string compare directly
	 * to make it work for longer pathnames. For now lets get the mechanics
	 * working with short names.
	 */
	char pathname[256] = {0};

	/* This is a bit parnoid but was previously having trouble on
	 * 4.14 kernels tracking offset of curr through filename_builder
	 * resulting in a a verifier error. We can optimize this a bit
	 * later perhaps and push as an argument.
	 */
	earg = (void *)curr + offsetof(struct event_execve, args);

	size = probe_read_str(earg, MAXARGLENGTH - 1, filename);
	if (size < 0) {
		flags |= EVENT_ERROR_FILENAME;
		size = 0;
	} else if (size == MAXARGLENGTH - 1) {
		flags |= EVENT_TRUNC_FILENAME;
	}
	curr->flags = flags;
	curr->pid = curr_pid;
	curr->nspid = get_task_pid_vnr();
	curr->ktime = ktime_get_ns();
	curr->size = size + offsetof(struct event_execve, args);

	probe_read_str(pathname, 255, filename);
	value = map_lookup_elem(&names_map, pathname);
	if (value)
		return *value;
	return 0;
}

#define PROBE_ARG_HEADER				\
	"%[index] = 0;"

#define PROBE_ARG_READ5 \
	PROBE_ARG_READ  \
	PROBE_ARG_READ  \
	PROBE_ARG_READ  \
	PROBE_ARG_READ  \
	PROBE_ARG_READ  \

#define PROBE_ARG_READ10 \
	PROBE_ARG_READ5  \
	PROBE_ARG_READ5

#define PROBE_ARG_READ50 \
	PROBE_ARG_READ10 \
	PROBE_ARG_READ10 \
	PROBE_ARG_READ10 \
	PROBE_ARG_READ10 \
	PROBE_ARG_READ10

/* The first argument is the command from cmdline but we already report the
 * filename so its redundant lets walk past it. Do we still need end check?
 * Left for now until we analyze a bit.
 */
#define PROBE_PAST_CMD					\
	"r3 = *(u64 *)%[args];"				\
	"r3 += %[offset];"				\
	"r4 = *(u64 *)%[end];"				\
	"if r4 <= r3 goto %l[c];"			\
	"r4 = *(u32 *)(%[curr] + 0);"			\
	"if r4 s< 0 goto %l[a];"			\
	"if r4 s> " XSTR(BUFFER) " goto %l[b];"		\
	"r1 = *(u64 *)%[earg];"				\
	"r1 += r4;"					\
	"r2 = " XSTR(MAXARGLENGTH) ";"			\
	"call 45;"					\
	"if r0 s< 0 goto %l[a];"			\
	"%[offset] += r0;"

#define PROBE_ARG_READ		     			\
	"r3 = *(u64 *)%[args];"				\
	"r3 += %[offset];"				\
	"r4 = *(u64 *)%[end];"				\
	"if r4 <= r3 goto %l[c];"			\
	"r4 = *(u32 *)(%[curr] + 0);"			\
	"if r4 s< 0 goto %l[a];"			\
	"if r4 s> " XSTR(BUFFER) " goto %l[b];"		\
	"r1 = *(u64 *)%[earg];"				\
	"r1 += r4;"					\
	"r2 = " XSTR(MAXARGLENGTH) ";"			\
	"call 45;"					\
	"if r0 s< 0 goto %l[a];"			\
	"%[offset] += r0;"				\
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
static inline __attribute__((always_inline))
void probe_arg_read(struct event_execve *c, char *earg, char *args, char *end_args)
{
	int off = 0;

	asm volatile goto (
			PROBE_PAST_CMD
			PROBE_ARG_READ50
		:
		: [earg]         "m"(earg),
		  [args]	 "m"(args),
		  [end]		 "m"(end_args),
		  [curr]	 "ri"(c),
		  [offset]	 "r"(off)
		: "r0", "r1", "r2", "r3", "r4", "r5"
		: a, b, c);
	c->flags |= EVENT_TRUNC_ARGS;
c:
	return;
b:
	c->flags |= EVENT_TRUNC_ARGS;
	return;
a:
	c->flags |= EVENT_ERROR_ARGS;
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
static inline __attribute__((always_inline))
void event_args_builder(struct msg_execve_event *event)
{
	struct task_struct *task = (struct task_struct *)get_current_task();
	struct event_execve *p, *c;
	struct mm_struct *mm;
	//int64_t base;

	/* Calculate absolute offset into buffer */
	c = (struct event_execve *)event->pid;
	c->auid = get_auid();
	p = c;

	/* We use flags in asm to indicate overflow */
	compiler_barrier();
	probe_read(&mm, sizeof(mm), _(&task->mm));
	if (mm) {
		long unsigned int start_stack, end_stack;

		probe_read(&start_stack, sizeof(start_stack), _(&mm->arg_start));
		probe_read(&end_stack, sizeof(start_stack), _(&mm->arg_end));
		if (start_stack && end_stack)
			probe_arg_read(c, (char*)p, (char *)start_stack, (char *)end_stack);
	}
	//c->size -= base;
	return;
}

static inline __attribute__((always_inline))
void event_cwd_builder(struct event_execve *process, __u32 curr_pid)
{
	getcwd(process, process->size, process->pid, 0);
}

static inline __attribute__((always_inline))
void event_set_clone(struct event_execve *pid)
{
	pid->flags |= EVENT_CLONE;
}

static inline __attribute__((always_inline))
int64_t event_copy_execve(struct event_execve *dst,
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

static inline __attribute__((always_inline))
__u32 event_find_parent_pid(struct task_struct *t)
{
	struct task_struct *task = get_parent(t);
	__u32 pid;

	if (!task)
		return 0;
	probe_read(&pid, sizeof(pid), _(&task->tgid));
	return pid;
}

static inline __attribute__((always_inline))
struct execve_map_value *event_find_parent(void)
{
	struct task_struct *task = (struct task_struct *)get_current_task();
	__u32 pid = get_current_pid_tgid() >> 32;
	struct execve_map_value *value = 0;
	int i;

#pragma unroll
	for (i = 0; i < 4; i++) {
		probe_read(&task, sizeof(task), _(&task->parent));
		if (!task)
			break;
		probe_read(&pid, sizeof(pid), _(&task->tgid));
		value = map_lookup_event(pid);
		if (value && value->key.ktime != 0)
			return value;
	}
	return 0;
}

static inline __attribute__((always_inline))
void event_minimal_parent(struct msg_execve_event *event, struct task_struct *task)
{
	event->parent.pid = event_find_parent_pid(task);
	event->parent.ktime = 0;
	event->parent_flags = EVENT_MISS;
}

static inline __attribute__((always_inline))
void event_minimal_curr(struct execve_map_value *event)
{
	event->key.pid = (get_current_pid_tgid() >> 32);
	event->key.ktime = 0; // should we insert a time?
	event->flags = EVENT_MISS;
}

static inline __attribute__((always_inline))
struct execve_map_value *event_find_curr(__u32 *ppid,
					 struct bpf_map_def *map,
					 bool *walked)
{
	struct task_struct *task = (struct task_struct *)get_current_task();
	__u32 pid = get_current_pid_tgid() >> 32;
	struct execve_map_value *value = 0;
	int i;

#pragma unroll
	for (i = 0; i < 4; i++) {
		value = map_lookup_event(pid);
		if (value && value->key.ktime != 0)
			break;
		value = 0;
		*walked = 1;
		probe_read(&task, sizeof(task), _(&task->parent));
		if (!task)
			break;
		probe_read(&pid, sizeof(pid), _(&task->tgid));
	}
	*ppid = pid;

	if (!value && map) {
		struct execve_map_value *parent;
		int zero = 0;

		value = map_lookup_event(zero);
		if (!value)
			return 0;
		parent = event_find_parent();
		if (parent)
			value->pkey = parent->pkey;
		else {
			value->pkey.ktime = 0;
			value->pkey.pid = 0;
		}
		event_minimal_curr(value);
	}
	return value;
}

static inline __attribute__((always_inline))
void get_caps(struct msg_execve_event *msg, struct task_struct *task)
{
	const struct cred *cred;

	probe_read(&cred, sizeof(cred), _(&task->real_cred));
	probe_read(&msg->caps.permitted, sizeof(__u64), _(&cred->cap_effective));
	probe_read(&msg->caps.effective, sizeof(__u64), _(&cred->cap_inheritable));
	probe_read(&msg->caps.inheritable, sizeof(__u64), _(&cred->cap_permitted));
}

/* Pahole bug does not convert to btf correctly with arbitrary byte holes not
 * near a cacheline. To work-around this we can specify a define with the
 * CGROUPS_OFFSET we read directly out of debug_info section. Note other
 * reads, subsys[], cgroup are the first element of the structure so we can
 * "just" read those. Then cid, kn, and name all appear to be before byte
 * holes on kernels I checked so leave them alone for now.
 *
 * Todo, fix pahole to avoid doing extra steps to lookup offsets.
 * Edit: pahole has been fixed need to update toolchain.
 */
static inline __attribute__((always_inline))
void __event_get_task_info(struct msg_execve_event *msg, __u8 op, bool walker, bool cwd_always)
{
	struct cgroup_subsys_state *subsys;
	struct event_execve *curr;
	struct task_struct *task;
	struct nsproxy *nsproxy;
	struct css_set *cgroups;
	struct kernfs_node *kn;
	struct cgroup *cgrp;
	struct net *net_ns;
	const char *name;

	msg->common.op = op;
	msg->common.ktime = ktime_get_ns();
	curr = (struct event_execve *)&msg->pid;

	if (cwd_always || curr->flags & EVENT_NEEDS_CWD) {
		__u32 offset;
		int err;
		bool prealloc = false;

		/* In the cwd always case we have no reserved memory for
		 * CWD so insert CWD directly after the curr->size. In
		 * EVENT_NEEDS_CWD case this is a procFS entry that we
		 * need to insert CWD for and memory has been reserved
		 * already. Finally if ERROR_CWD flag is set skip there
		 * is no point in continuing to bang on it if its not
		 * working.
		 */
		offset = curr->size;
		if (!cwd_always) {
			offset -= CWD_MAX + 1;
			prealloc = true;
		}
		if (!(curr->flags & EVENT_ERROR_CWD)) {
			err = getcwd(curr, offset, curr->pid, prealloc);
			if (!err)
				curr->flags = curr->flags & ~(EVENT_NEEDS_CWD | EVENT_ERROR_CWD);
		}
	}
	if (curr->flags & EVENT_NEEDS_AUID) {
		__u32 flags = curr->flags & ~EVENT_NEEDS_AUID;

		curr->auid = get_auid();
		curr->flags = flags;
	}
	msg->common.size = offsetof(struct msg_execve_event, pid) + curr->size;
	curr->uid = get_current_uid_gid();
	if (walker)
		curr->flags |= EVENT_TASK_WALK;

	task = (struct task_struct *)get_current_task();
	probe_read(&nsproxy, sizeof(nsproxy), _(&task->nsproxy));
	if (nsproxy) {
		probe_read(&net_ns, sizeof(net_ns), _(&nsproxy->net_ns));
		if (net_ns)
			probe_read(&msg->kube.net_ns, sizeof(msg->kube.net_ns), _(&net_ns->ns.inum));
	}

	task = (struct task_struct *)get_current_task();
	probe_read(&cgroups, sizeof(cgroups), _(&task->cgroups));
	if (cgroups) {
		probe_read(&subsys, sizeof(subsys), _(&cgroups->subsys[0]));
		if (subsys) {
			probe_read(&cgrp, sizeof(cgrp), _(&subsys->cgroup));
			if (cgrp) {
				probe_read(&kn, sizeof(cgrp->kn), _(&cgrp->kn));
				if (kn) {
					probe_read(&name, sizeof(name), _(&kn->name));
					if (name) {
						probe_read_str(msg->kube.docker_id,
							       DOCKER_ID_LENGTH,
							       name);
					} else {
						curr->flags |= EVENT_DOCKER_NAME_ERR;
					}
				}
				// else case we do not include error flag because it
				// indicates there is not a docker id. This is normal
				// in the case process is in host namespace.
			} else {
				curr->flags |= EVENT_DOCKER_SUBSYSCGRP_ERR;
			}
		} else {
			curr->flags |= EVENT_DOCKER_SUBSYS_ERR;
		}
	} else {
		curr->flags |= EVENT_DOCKER_CGROUPS_ERR;
	}
#ifdef BPF_FUNC_get_current_cgroup_id
	msg->kube.cgrpid = get_current_cgroup_id();
#endif
	get_caps(msg, task);
}

static inline __attribute__((always_inline))
void event_get_task_info(struct msg_execve_event *msg, __u8 op, bool walker)
{
	__event_get_task_info(msg, op, walker, false);
}

static inline __attribute__((always_inline))
struct event_execve *event_get_curr_execve(struct msg_execve_event *msg)
{
	return (struct event_execve *)msg->pid;
}

static inline __attribute__((always_inline))
void add_socketmap(struct msg_tls_ipv4 *tuple, struct socketmap_value *v)
{
	int err = map_update_elem(&socket_map, tuple, v, 0);
	int zero = 0;
	__s64 *cntr;

	if (!err && (cntr = map_lookup_elem(&socket_map_stats, &zero)))
		*cntr = *cntr + 1;
}

static inline __attribute__((always_inline))
void del_socketmap(struct msg_tls_ipv4 *tuple)
{
	int err = map_delete_elem(&socket_map, tuple);
	int zero = 0;
	__s64 *cntr;

	if (!err && (cntr = map_lookup_elem(&socket_map_stats, &zero)))
		*cntr = *cntr - 1;
}

static inline __attribute__((always_inline))
struct socketmap_value *lookup_socketmap(struct msg_tls_ipv4 *tuple)
{
	return map_lookup_elem(&socket_map, tuple);
}

static inline __attribute__((always_inline))
int is_tuple_local(struct msg_tls_ipv4 *tuple)
{
	return (tuple->daddr & 0xff) == 127 || // daddr lo addr
	       (tuple->saddr & 0xff) == 127 || // saddr lo addr
	       tuple->daddr == 0;              // listening socket no addr always local
}
#endif // _BPF_EVENTS_H
