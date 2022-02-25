
/**
 * Process filters
 * see generic_process_filter below
 */

#define FIND_PIDSET(value, isns)  {			\
	if (!filter)					\
		return 0;				\
	{						\
	__u32 pid, ppid = 0;				\
	if (isns) {					\
		pid = filter->nspid;			\
	} else {					\
		pid = filter->key.pid;			\
		ppid = filter->pkey.pid;		\
	}					\
	if (pid == value || ppid == value) {		\
		pidset_found = true;			\
		goto accept;				\
	}						\
	}						\
	filter = map_lookup_elem(&execve_map, &filter->pkey.pid); \
}

#define FIND_PIDSET10(VAL, ISNS) {	\
	FIND_PIDSET(VAL, ISNS)		\
	FIND_PIDSET(VAL, ISNS)		\
	FIND_PIDSET(VAL, ISNS)		\
	FIND_PIDSET(VAL, ISNS)		\
	FIND_PIDSET(VAL, ISNS)		\
	FIND_PIDSET(VAL, ISNS)		\
	FIND_PIDSET(VAL, ISNS)		\
	FIND_PIDSET(VAL, ISNS)		\
	FIND_PIDSET(VAL, ISNS)		\
}

#define FILTER_PIDSET(VAL) {	\
	FIND_PIDSET10(VAL)	\
}

static inline __attribute__((always_inline))
bool filter_pidset(__u64 sel, __u64 isns, struct execve_map_value *enter)
{
	struct execve_map_value *filter = enter;
	bool pidset_found = false;

	FIND_PIDSET10(sel, isns);
accept:
	return pidset_found;
}

#define PID_SELECTOR_FLAG_NSPID 0x1
#define PID_SELECTOR_FLAG_FOLLOW 0x2

static inline __attribute__((always_inline))
bool filter_pidsets(__u64 ty,
		    __u64 flags,
		    __u64 sel,
		    struct execve_map_value *enter)
{
	bool found;
	__u64 isns = flags & PID_SELECTOR_FLAG_NSPID;

	/* If nspid rule and entry is not in a namespace drop it */
	if (isns && !enter->nspid)
		return 0;
	found = filter_pidset(sel, isns, enter);
	if (ty == op_filter_pid_in && !found)
		return 0;
	else if (ty == op_filter_pid_notin && found)
		return 0;
	return 1;
}

// generic_process_filter return value
enum  {
	PFILTER_ERROR = 3,	     // these should never happen
	PFILTER_CONTINUE = 2,        // filter check continue
	PFILTER_ACCEPT = 1,          // filter check passed
	PFILTER_REJECT = 0,          // filter check failed
	PFILTER_CURR_NOT_FOUND = 0,  // event_find_curr() failed
};

static inline  __attribute__((always_inline))
int __process_filter_pid(__u64 ty, __u64 flags, __u64 sel, __u64 pid,
		   struct execve_map_value *enter)
{
	if (flags & PID_SELECTOR_FLAG_FOLLOW) {
		bool accept_pid = filter_pidsets(ty, flags, sel, enter);

		if (!accept_pid)
			return PFILTER_REJECT;
		return PFILTER_ACCEPT;
	} else {
		if (ty == op_filter_pid_in && sel != pid)
			return PFILTER_REJECT;
		else if (ty == op_filter_pid_notin && sel == pid)
			return PFILTER_REJECT;
		return PFILTER_ACCEPT;
	}
}

static inline __attribute__((always_inline))
int next_pid_value(__u32 off, __u32 *f, __u32 ty)
{
	return off + 4;
}

static inline __attribute__((always_inline))
int process_filter_pid(__u32 i, __u32 off, __u32 *f, __u64 ty, __u64 flags,
		   struct execve_map_value *enter, void *heap)
{
	__u32 sel;
	__u64 pid;

	if (flags & PID_SELECTOR_FLAG_NSPID) {
		pid = enter->nspid;
	} else {
		pid = enter->key.pid;
	}

	if (off > 1000)
		sel = 0;
	else {
		__u64 o = (__u64)off;
		o = o / 4;
		asm volatile("%[o] &= 0x3ff;\n":: [o] "+r" (o):);
		sel = f[o];
	}
	return __process_filter_pid(ty, flags, sel, pid, enter);
}

#define MAX_SELECTOR_VALUES 4

static inline __attribute__((always_inline))
int selector_match(__u32 *f, __u32 index, __u64 ty, __u64 flags, __u64 len,
			struct execve_map_value *enter, void *heap,
			int (*process_filter)(__u32, __u32, __u32 *, __u64, __u64, struct execve_map_value *, void *))
{
	int res1 = 0, res2 = 0, res3 = 0, res4 = 0;

	/* For NotIn op we AND results so default to 1 so we fallthru open */
	if (ty == op_filter_pid_notin)
		res1 = res2 = res3 = res4 = 1;

	/* Unrolling this loop was problematic for clang so rather
	 * than fight with clang just open code it. Its hard to see
	 * how many pid values will be used anyways. Having zero
	 * length values is an input error that CRD should catch.
	 */
	if (len == 4) goto four;
	else if (len == 3) goto three;
	else if (len == 2) goto two;
	else if (len == 1) goto one;
four:
	res4 = process_filter(3, index, f, ty, flags, enter, heap);
	index = next_pid_value(index, f, ty);
three:
	res3 = process_filter(2, index, f, ty, flags, enter, heap);
	index = next_pid_value(index, f, ty);
two:
	res2 = process_filter(1, index, f, ty, flags, enter, heap);
	index = next_pid_value(index, f, ty);
one:
	res1 = process_filter(0, index, f, ty, flags, enter, heap);
	index = next_pid_value(index, f, ty);

	if (ty == op_filter_pid_notin)
		return res1 & res2 & res3 & res4;
	else
		return res1 | res2 | res3 | res4;
}

static inline __attribute__((always_inline))
int selector_process_filter(__u32 *f, __u32 index, struct execve_map_value *enter, void *heap)
{
	__u64 pid, ty = 0, flags = 0, len = 0;
	__u64 tmp = 0;

	/* Find selector offset byte index */
	index *= 4;
	index += 4;

	/* This is a bit unfortunate but if we try to write C code with
	 * a loop for this compiler generates code,
	 *
	 * r3 = r4
	 * r2 = w9
	 * if w2 > 0x400 goto pc ...
	 * r9 = *(u32 *)(r2 +0)
	 * r0 = *(u32 *)(r3 +0)
	 *
	 * The problem here is compiler is "smart" enough to know that r4
	 * is also w9 and can skip the bounds check, but the verifier on
	 * the other hand is not smart enough to track this. The result is
	 * we get a verifier error.
	 */
	asm volatile (
	"%[index] &= 0x3ff;\n"
	"%[t] = %[m];\n"                    /* tmp = f; */
	"%[t] += %[index];\n"               /* tmp =+ index; */
	"%[index] = *(u32 *)(%[t] + 0);\n"  /* index = *(u32 *)tmp; */
	"%[index] &= 0x3ff;\n"
	"%[t] = %[m];\n"                    /* tmp = f; */
	"%[t] += %[index];\n"               /* tmp += index; */
	"%[ty] = *(u32 *)(%[t] +12);\n"     /* ty = *(u32 *)(tmp + 12); */ /* +12 to step past headers */
	"%[flags] = *(u32 *)(%[t] +16);\n"  /* flags = *(u32 *)(tmp + 16); */
	"%[len] = *(u32 *)(%[t] +20);\n"    /* len = *(u32 *)(tmp + 20); */
	: [index] "+r"(index),
	  [len] "+r"(len),
	  [flags] "+r"(flags),
	  [ty] "+r"(ty),
	  [m] "+r"(f),
	  [t] "+r"(tmp)
	::);

	/* offset into values
	 * 4: uint32 selector value
	 * 8: selector header, pid header
	 * 12: op, flags, length
	 */
	index += 4 + 8 + 12;

	return selector_match(f, index, ty, flags, len, enter, heap, &process_filter_pid);
}

#define MAX_SELECTORS 8

static inline __attribute__((always_inline))
int process_filter_done(struct msg_generic_kprobe *msg,
			struct execve_map_value *enter,
			struct msg_execve_key *current)
{
	current->pid = enter->key.pid;
	current->ktime = enter->key.ktime;
	if (msg->pass) {
		return PFILTER_ACCEPT;
	}
	return PFILTER_REJECT;
}

// generic_process_filter performs first pass filtering based on pid/nspid.
// We keep a list of selectors that pass.
//
// if filter check was successful, it will return PFILTER_ACCEPT and properly
// set the values of:
//    current->pid
//    current->ktime
// for the memory located at index 0 of @msg_heap assuming the value follows the
// msg_generic_hdr structure.
static inline  __attribute__((always_inline))
int generic_process_filter(struct msg_generic_kprobe *msg, void *fmap, void *heap)
{
	struct msg_execve_key *current = &msg->current;
	struct execve_map_value *enter;
	bool walker = 0;
	__u32 ppid;
	int curr;

	enter = event_find_curr(&ppid, 0, &walker);
	if (enter) {
		int zero = 0, selectors, pass;
		__u32 *f = map_lookup_elem(fmap, &zero);

		if (!f)
			return PFILTER_ERROR;

		curr = msg->curr;
		if (curr > MAX_SELECTORS)
			return process_filter_done(msg, enter, current);

		selectors = f[0];
		/* If no selectors accept process */
		if (!selectors) {
			msg->pass = true;
			return process_filter_done(msg, enter, current);
		}

		/* If we get here with reference to uninitialized selector drop */
		if (selectors <= curr)
			return process_filter_done(msg, enter, current);

		pass = selector_process_filter(f, curr, enter, heap); /* matches the PID */
		if (pass) {
			/* Verify lost that msg is not null here so recheck */
			asm volatile("%[curr] &= 0x1f;\n":: [curr] "r+" (curr):);
			msg->active[curr] = true;
			msg->active[SELECTORS_ACTIVE] = true;
			msg->pass |= true;
		}
		msg->curr++;
		if (msg->curr > selectors)
			return process_filter_done(msg, enter, current);
		return PFILTER_CONTINUE; /* will iterate to the next selector */
	}
	return PFILTER_CURR_NOT_FOUND;
}
