#ifndef _BPF_EVENTS_H
#define _BPF_EVENTS_H

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
int64_t validate_msg_size(int64_t size)
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

static inline __attribute__((always_inline))
__u32 __get_auid(struct task_struct *task)
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
#else // AUDIT_STRUCT
	char *addr;

#ifdef AUID_OFFSET
	addr = (void *)task;
	addr += AUID_OFFSET;
#else
	addr = (void *)&(task->loginuid.val);
#endif // AUID_OFFSET
	probe_read(&auid, sizeof(auid), addr);
#endif // AUDIT_STRUCT

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

	probe_read(&task, sizeof(task), &t->parent);
	if (!task)
		return 0;
	return task;
}

static inline __attribute__((always_inline))
__u32 get_parent_auid(struct task_struct *t)
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
		probe_read(&cpid, sizeof(cpid), &task->pid);
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
	CWD_DENTRY_REG " = *(u64 *)%[dentry];"			\
	CWD_VFSMNT_DENTRY_REG " = *(u64 *)%[vfsmnt];"		\
	CWD_OFFSET_REG " = *(u32 *)%[offset];"			\
	"r3 = *(u64 *)%[curr];"					\
	"*(u64 *)(r3 + 0) = " CWD_OFFSET_REG ";"

#define PROBE_CWD_READ	  	   			\
	/* if (!dentry) { break; } */			\
	"r3 = " CWD_DENTRY_REG ";"			\
	"if r3 == 0 goto %l[a];"			\
	/* probe_read(&parent, sizeof(parent), &dentry->d_parent); */ \
	"r3 += %[dentry_parent];"			\
	"r2 = 8;"					\
	"r1 = %[ptr];"					\
	"call 4;"					\
	/* if (!parent) { break; } */			\
	"r4 = *(u64 *)(%[ptr] + 0);"			\
	"if r4 == 0x0 goto %l[a];"			\
	/* if (vfsmnt_dentry && dentry == vfsmnt_dentry) { */ \
	"if " CWD_VFSMNT_DENTRY_REG " == " CWD_DENTRY_REG " goto %l[a];" \
	/* name = &dentry->d_name; */			\
	/* dentry = parent; */				\
	/* probe_read(&dname, sizeof(dname), &name->name); */ \
	"r3 = " CWD_DENTRY_REG ";"			\
	"r3 += %[dentry_name];"				\
	CWD_DENTRY_REG " = r4;" /* r9 = parent */	\
	"r1 = %[ptr];"					\
	"r2 = 8;"					\
	"call 4;"					\
	/* pcwd = curr + offset */			\
	/* probe_read(pcwd, 1, &slash); */		\
	"r1 = *(u64 *)%[pid];"				\
	"if " CWD_OFFSET_REG " s< 0 goto %l[a];"	\
	"if " CWD_OFFSET_REG " s> 1188 goto %l[a];"	\
	"r1 += " CWD_OFFSET_REG ";"\
	"r2 = 1;"					\
	"r3 = *(u64 *)%[slash];"			\
	"call 4;"					\
	/* pcwd++; */					\
	/* ret = probe_read_str(pcwd, CWD_MAX, dname); */ \
	CWD_OFFSET_REG " += 1;"				\
	"r1 = *(u64 *)%[pid];"				\
	"if " CWD_OFFSET_REG " < 0 goto %l[a];"	\
	"if " CWD_OFFSET_REG " > 1188 goto %l[a];"	\
	"r1 += " CWD_OFFSET_REG ";"			\
	"r2 = " XSTR(CWD_MAX) ";"			\
	"r3 = *(u64 *)(%[ptr] + 0);"			\
	"call 45;"					\
	/* if (ret < 0) { */				\
	/* cwdsize += ret */				\
	"if r0 s< 1 goto %l[a];"				\
	"r0 -= 1;"					\
	CWD_OFFSET_REG " += r0;"			\
	"r3 = *(u64 *)%[curr];"				\
	"*(u64 *)(r3 + 0) = " CWD_OFFSET_REG ";"

static inline __attribute__((always_inline))
int64_t getcwd(struct event_execve *curr, struct event_execve *pid,
	       __u32 offset, __u32 proc_pid, bool prealloc)
{
	struct task_struct *task = get_task_from_pid(proc_pid);
	struct dentry *dentry, *vfsmnt_dentry;
	struct vfsmount *vfsmnt;
	struct path pwd;
	struct fs_struct *fs;
	void *ptr;
	char slash = '/';
	char *pslash = &slash;
	__u32 orig_size = curr->size, orig_offset = offset;
	int dentry_parent, dentry_name;

	probe_read(&fs, sizeof(fs), &task->fs);
	if (!fs) {
		curr->flags |= EVENT_ERROR_CWD;
		return 0;
	}

	probe_read(&pwd, sizeof(pwd), &fs->pwd);
	dentry = pwd.dentry;
	vfsmnt = pwd.mnt;
	probe_read(&vfsmnt_dentry, sizeof(vfsmnt_dentry), &vfsmnt->mnt_root);

	dentry_parent = offsetof(struct dentry, d_parent);
	dentry_name = offsetof(struct dentry, d_name) + offsetof(struct qstr, name);

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
		: [curr]   "=m"(curr),
		  [pid]    "=m"(pid),
		  [vfsmnt] "m"(vfsmnt_dentry),
		  [dentry] "m"(dentry),
		  [ptr]    "+r"(&ptr),
		  [slash]  "m"(pslash),
		  [offset] "+m"(offset),
		  [dentry_parent] "i"(dentry_parent),
		  [dentry_name] "i"(dentry_name)
		: "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r9"
		: a);
a:
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
	else
		curr->size = orig_size + (curr->size - orig_offset);
	return 0;
}

static inline __attribute__((always_inline))
void event_filename_builder(struct event_execve *pid,
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
		if (size < 0) {
			flags |= EVENT_ERROR_FILENAME;
			size = 0;
		} else if (size == MAXARGLENGTH - 1) {
			flags |= EVENT_TRUNC_FILENAME;
		}
	}
	curr->flags = flags;
	curr->pid = curr_pid;
	curr->ktime = ktime_get_ns();
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
	"if r3 == 0 goto %l[c];"			\
	"r4 = *(u32 *)(%[curr] + 0);"			\
	"if r4 s< 0 goto %l[a];"			\
	"if r4 s> " XSTR(BUFFER) " goto %l[b];"		\
	"r1 = %[earg];"					\
	"r1 += r4;"					\
	"r2 = " XSTR(MAXARGLENGTH) ";"			\
	"call 45;"					\
	"if r0 s< 0 goto %l[a];"			\
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
void probe_arg_read(struct event_execve *c, char *earg, char **args)
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
		: a, b, c);
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
void event_args_builder(struct msg_ipv4_tcp_connect *event, void *pargs)
{
	struct event_execve *p, *c;
	int64_t base;
	char **args;

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
	probe_arg_read(c, (char*)p, args);
	c->size -= base;
	return;
}

static inline __attribute__((always_inline))
void event_cwd_builder(struct event_execve *pid, __u32 curr_pid)
{
	struct event_execve *c;
	int64_t psize;

	psize = validate_arg_size(pid->size);
	c = (void *)pid + psize;
	getcwd(c, pid, psize + c->size, c->pid, 0);
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
	probe_read(&pid, sizeof(pid), &task->pid);
	return pid;
}

static inline __attribute__((always_inline))
struct msg_ipv4_tcp_connect *event_find_parent(void)
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
		if (msg && msg->common.size != 0)
				return msg;
	}
	return 0;
}

static inline __attribute__((always_inline))
void event_minimal_parent(struct event_execve *event, struct task_struct *task)
{
	__u32 size = offsetof(struct event_execve, args);

	event->size = size;
	event->pid = event_find_parent_pid(task);
	event->auid = get_parent_auid(task);
	event->flags = EVENT_MISS;
	event->uid = 0;
}

static inline __attribute__((always_inline))
void event_minimal_curr(struct event_execve *event)
{
	__u32 size = offsetof(struct event_execve, args);

	event->size = size;
	event->pid = (get_current_pid_tgid() >> 32);
	event->auid = get_auid();
	event->flags = EVENT_MISS;
	event->uid = 0;
}

static inline __attribute__((always_inline))
struct msg_ipv4_tcp_connect *event_find_curr(__u32 *ppid,
					     struct bpf_map_def *map,
					     bool *walked)
{
	struct task_struct *task = (struct task_struct *)get_current_task();
	__u32 pid = get_current_pid_tgid() >> 32;
	struct msg_ipv4_tcp_connect *msg = 0;
	char *addr;
	int i;

#pragma unroll
	for (i = 0; i < 4; i++) {
		msg = map_lookup_elem(&execve_map, &pid);
		if (msg && msg->common.size != 0)
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

	if (!msg && map) {
		struct msg_ipv4_tcp_connect *parent_event;
		struct event_execve *parent, *curr;
		int zero = 0;
		ssize_t size;

		msg = map_lookup_elem(map, &zero);
		if (!msg)
			return 0;
		parent = (struct event_execve *)msg->pid;
		parent_event = event_find_parent();
		if (parent_event)
			event_copy_execve(parent,
					  (struct event_execve *)&parent_event->pid);
		else
			event_minimal_parent(parent, task);
		size = validate_arg_size(parent->size);
		curr = (void *)parent + size;
		msg->common.size = 1;
		event_minimal_curr(curr);
	}
	return msg;
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
void event_get_task_info(struct msg_ipv4_tcp_connect *msg, __u8 op, bool walker)
{
	struct cgroup_subsys_state *subsys;
	struct event_execve *curr, *parent;
	struct task_struct *task;
	struct nsproxy *nsproxy;
	struct css_set *cgroups;
	struct kernfs_node *kn;
	struct cgroup *cgrp;
	struct net *net_ns;
	const char *name;
	ssize_t size;
	char *addr;

	msg->common.op = op;
	msg->common.ktime = ktime_get_ns();
	parent = (struct event_execve *)&msg->pid;

	if (parent->flags & EVENT_NEEDS_CWD) {
		getcwd(parent, parent, parent->size - CWD_MAX + 1, parent->pid, 1);
		parent->flags = parent->flags & ~EVENT_NEEDS_CWD;
	}
	if (parent->flags & EVENT_NEEDS_AUID) {
		__u32 flags = parent->flags & ~EVENT_NEEDS_AUID;

		parent->auid = get_auid();
		parent->flags = flags;
	}

	size = validate_arg_size(parent->size);
	curr = (void *)parent + size;
	if (curr->flags & EVENT_NEEDS_CWD) {
		getcwd(curr, parent, parent->size + curr->size - CWD_MAX + 1, curr->pid, 1);
		curr->flags = curr->flags & ~EVENT_NEEDS_CWD;
	}
	if (curr->flags & EVENT_NEEDS_AUID) {
		__u32 flags = curr->flags & ~EVENT_NEEDS_AUID;

		curr->auid = get_auid();
		curr->flags = flags;
	}
	msg->common.size = offsetof(struct msg_ipv4_tcp_connect, pid) + parent->size + curr->size;
	curr->uid = get_current_uid_gid();
	if (walker)
		curr->flags |= EVENT_TASK_WALK;

	task = (struct task_struct *)get_current_task();
	probe_read(&nsproxy, sizeof(nsproxy), &(task->nsproxy));
	if (nsproxy) {
		probe_read(&net_ns, sizeof(net_ns), &(nsproxy->net_ns));
		if (net_ns)
			probe_read(&msg->kube.net_ns, sizeof(msg->kube.net_ns), &(net_ns->ns.inum));
	}

	task = (struct task_struct *)get_current_task();
#ifdef CGROUPS_OFFSET
	addr = (void *)task;
	addr += CGROUPS_OFFSET;
#else
	addr = (void *)&(task->cgroups);
#endif
	probe_read(&cgroups, sizeof(cgroups), addr);
	if (cgroups) {
		probe_read(&subsys, sizeof(subsys), &(cgroups->subsys[0]));
		if (subsys) {
			probe_read(&cgrp, sizeof(cgrp), &(subsys->cgroup));
			if (cgrp) {
#ifdef CGROUPS_KN_OFFSET
				addr = (void *)(cgrp);
				addr += CGROUPS_KN_OFFSET;
#else
				addr = (void *)&(cgrp->kn);
#endif
				probe_read(&kn, sizeof(cgrp->kn), addr);
				if (kn) {
					probe_read(&name, sizeof(name), &(kn->name));
					if (name)
						probe_read_str(msg->kube.docker_id,
							       DOCKER_ID_LENGTH,
							       name);
				}
			}
		}
	}
#ifdef BPF_FUNC_get_current_cgroup_id
	msg->kube.cgrpid = get_current_cgroup_id();
#endif
}

#ifdef USE_HASH_MAP
static inline __attribute__((always_inline))
void map_update_hash(struct msg_ipv4_tcp_connect *event,
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

static inline __attribute__((always_inline))
struct msg_ipv4_tcp_connect *map_lookup_event(__u32 pid)
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
static inline __attribute__((always_inline))
void map_update_hash(struct msg_ipv4_tcp_connect *event,
		     __u32 pid)
{
}

static inline __attribute__((always_inline))
struct msg_ipv4_tcp_connect *map_lookup_event(__u32 pid)
{
	return map_lookup_elem(&execve_map, &pid);
}
#endif
#endif // _BPF_EVENTS_H
