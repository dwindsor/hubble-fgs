
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
	filter = map_lookup_event(filter->pkey.pid);	\
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
bool filter_pidset(int sel, int isns, struct execve_map_value *enter)
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
bool filter_pidsets(__u32 ty,
		    __u32 flags,
		    __u32 sel,
		    struct execve_map_value *enter)
{
	bool found;
	int isns = flags & PID_SELECTOR_FLAG_NSPID;

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
	PFILTER_PASSED = 1,          // filter check passed
	PFILTER_FAILED = 0,          // filter check failed
	PFILTER_CURR_NOT_FOUND = 0,  // event_find_curr() failed
};

static inline  __attribute__((always_inline))
int __process_filter(__u32 ty, __u32 flags, __u32 sel, __u32 pid,
		   struct execve_map_value *enter)
{
	if (flags & PID_SELECTOR_FLAG_FOLLOW) {
		bool accept_pid = filter_pidsets(ty, flags, sel, enter);

		if (!accept_pid)
			return PFILTER_FAILED;
		return PFILTER_PASSED;
	} else {
		if (ty == op_filter_pid_in && sel != pid)
			return PFILTER_FAILED;
		else if (ty == op_filter_pid_notin && sel == pid)
			return PFILTER_FAILED;
		return PFILTER_PASSED;
	}
}

static inline __attribute__((always_inline))
int next_pid_value(__u32 off, __u32 *f, __u32 ty)
{
	return off + 4;
}

static inline __attribute__((always_inline))
int process_filter(__u32 i, __u32 off, __u32 *f, __u32 ty, __u32 flags, __u32 pid,
		   struct execve_map_value *enter)
{
	__u32 sel;

	if (off > 1000)
		sel = 0;
	else
		sel = f[off/4];

	return __process_filter(ty, flags, sel, pid, enter);
}

static inline __attribute__((always_inline))
int selector_process_filter(__u32 *f,
			    __u32 index,
			    struct execve_map_value *enter)
{
	__u32 pid, ty = 0, flags = 0, len = 0;
	__u64 tmp = 0;
	int res1, res2, res3, res4;

	res1 = res2 = res3 = res4 = 0;

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
	"if %[index] > 68 goto +9;\n"
	"%[t] = %[m];\n"
	"%[t] += %[index];\n"
	"%[index] = *(u32 *)(%[t] + 0);\n"
	"if %[index] > 1008 goto +5;\n"
	"%[t] = %[m];\n"
	"%[t] += %[index];\n"
	"%[ty] = *(u32 *)(%[t] +12);\n"     // +12 to step past headers
	"%[flags] = *(u32 *)(%[t] +16);\n"
	"%[len] = *(u32 *)(%[t] +20);\n"
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

	if (flags & PID_SELECTOR_FLAG_NSPID) {
		pid = enter->nspid;
	} else {
		pid = enter->key.pid;
	}

#define MAX_SELECTOR_VALUES 4
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
	res4 = process_filter(3, index, f, ty, flags, pid, enter);
	index = next_pid_value(index, f, ty);
three:
	res3 = process_filter(2, index, f, ty, flags, pid, enter);
	index = next_pid_value(index, f, ty);
two:
	res2 = process_filter(1, index, f, ty, flags, pid, enter);
	index = next_pid_value(index, f, ty);
one:
	res1 = process_filter(0, index, f, ty, flags, pid, enter);
	index = next_pid_value(index, f, ty);

	return res1 | res2 | res3 | res4;
}

// generic_process_filter performs first pass filtering based on pid/nspid.
// We keep a list of selectors that pass.
//
// if filter check was successful, it will return PFILTER_PASSED and properly
// set the values of:
//    current->pid
//    current->ktime
// for the memory located at index 0 of @msg_heap assuming the value follows the
// msg_generic_hdr structure.
static inline  __attribute__((always_inline))
int generic_process_filter(struct msg_generic_kprobe *msg, void *fmap)
{
	struct msg_execve_key *current = &msg->current;
	struct execve_map_value *enter;
	bool walker = 0;
	__u32 ppid;

	msg->s7 = msg->s6 = msg->s5 = msg->s4 = msg->s3 = msg->s2 = msg->s1 = msg->s0 = 0;
	enter = event_find_curr(&ppid, 0, &walker);
	if (enter) {
		bool pass7, pass6, pass5, pass4, pass3, pass2, pass1, pass0;
		int zero = 0, selectors;
		__u32 *f = map_lookup_elem(fmap, &zero);

		if (!f)
			return 0;
		pass7 = pass6 = pass5 = pass4 = pass3 = pass2 = pass1 = pass0 = 0;
		selectors = f[0];
		if (selectors == 0) goto selpass;
		if (selectors == 1) goto sel1;
		if (selectors == 2) goto sel2;
		if (selectors == 3) goto sel3;
		if (selectors == 4) goto sel4;
		if (selectors == 5) goto sel5;
		if (selectors == 6) goto sel6;
		if (selectors == 7) goto sel7;
		if (selectors == 8) goto sel8;
sel8:
		pass7 = selector_process_filter(f, 7, enter);
		if (pass7)
			msg->s7 = true;
sel7:
		pass6 = selector_process_filter(f, 6, enter);
		if (pass6)
			msg->s6 = true;
sel6:
		pass5 = selector_process_filter(f, 5, enter);
		if (pass5)
			msg->s5 = true;
sel5:
		pass4 = selector_process_filter(f, 4, enter);
		if (pass4)
			msg->s4 = true;
sel4:
		pass3 = selector_process_filter(f, 3, enter);
		if (pass3)
			msg->s3 = true;
sel3:
		pass2 = selector_process_filter(f, 2, enter);
		if (pass2)
			msg->s2 = true;
sel2:
		pass1 = selector_process_filter(f, 1, enter);
		if (pass1)
			msg->s1 = true;
sel1:
		pass0 = selector_process_filter(f, 0, enter);
		if (pass0)
			msg->s0 = true;

		if (!(pass0 | pass1 | pass2 | pass3 | pass4 | pass5 | pass6 | pass7))
			return PFILTER_FAILED;
selpass:
		current->pid = enter->key.pid;
		current->ktime = enter->key.ktime;
		return PFILTER_PASSED;
	}
	return PFILTER_CURR_NOT_FOUND;
}
