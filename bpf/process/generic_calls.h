#define MAX_TOTAL 9000

static inline __attribute__((always_inline))
int generic_process_event0(
	struct pt_regs *ctx,
	struct bpf_map_def *heap_map,
	struct bpf_map_def *args0_filter_map,
	struct bpf_map_def *tailcals)
{
	enum generic_func_args_enum fgs_args;
	struct execve_map_value *enter;
	struct msg_generic_kprobe *e;
	unsigned long a0, a1, a2, a3, a4;
	bool walker = 0;
	__u32 pid, ppid;
	int zero = 0;
	/* total is used as a pointer offset so we want type to match
	 * pointer type in order to avoid bit shifts.
	 */
	long ty, total = 0;

	enter = event_find_curr(&ppid, 0, &walker);
	if (!enter)
		return 0;

	pid = get_current_pid_tgid() & 0xFFFFffff;
	// get e again to help verifier
	e = map_lookup_elem(heap_map, &zero);
	if (!e)
		return 0;

	a0 = e->a0;
	a1 = e->a1;
	a2 = e->a2;
	a3 = e->a3;
	a4 = e->a4;

	e->common.flags = 0;
	e->common.pad[0] = 0;
	e->common.pad[1] = 0;
	e->common.size = 0;
	e->common.ktime = ktime_get_ns();

	e->current.pad[0] = 0;
	e->current.pad[1] = 0;
	e->current.pad[2] = 0;
	e->current.pad[3] = 0;

	e->id = bpf_core_enum_value(fgs_args, func_id);
	/* Read out args1-5 */
	ty = bpf_core_enum_value(fgs_args, arg0);
	if (total < MAX_TOTAL) {
		void *map = args0_filter_map;
		unsigned long a0m, arg_meta;
		long errv;

		a0m = bpf_core_enum_value(fgs_args, arg0m);
		arg_meta = get_arg_meta(a0m, a0, a1, a2, a3, a4);
		errv = read_call_arg(e->args, ty, total, a0, arg_meta, map, enter);
		if (errv < 0)
			return 0;
		total += errv;
	}
	e->common.size = total;
	tail_call(ctx, tailcals, 1);
	return 0;
}

static inline __attribute__((always_inline))
int generic_process_event_and_setup(
	struct pt_regs *ctx,
	struct bpf_map_def *heap_map,
	struct bpf_map_def *args0_filter_map,
	struct bpf_map_def *tailcals)
{
	enum generic_func_args_enum fgs_args;
	struct msg_generic_kprobe *e;
	int zero = 0, is_syscall;

	/* Pid/Ktime Passed through per cpu map in process heap. */
	e = map_lookup_elem(heap_map, &zero);
	if (!e)
		return 0;

	is_syscall = bpf_core_enum_value(fgs_args, syscall);
	if (is_syscall) {
		struct pt_regs *_ctx;
		_ctx = (struct pt_regs *)ctx->di;
		if (!_ctx)
			return 0;
		probe_read(&e->a0, sizeof(e->a0), &_ctx->di);
		probe_read(&e->a1, sizeof(e->a1), &_ctx->si);
		probe_read(&e->a2, sizeof(e->a2), &_ctx->dx);
		probe_read(&e->a3, sizeof(e->a3), &_ctx->cx);
		probe_read(&e->a4, sizeof(e->a4), &_ctx->r8);
	} else {
		e->a0 = ctx->di;
		e->a1 = ctx->si;
		e->a2 = ctx->dx;
		e->a3 = ctx->cx;
		e->a4 = ctx->r8;
	}
	e->common.op = MSG_OP_GENERIC_KPROBE;
	return generic_process_event0(ctx, heap_map, args0_filter_map, tailcals);
}

static inline __attribute__((always_inline))
int generic_process_event1(
	void *ctx,
	struct bpf_map_def *heap_map,
	struct bpf_map_def *args1_filter_map,
	struct bpf_map_def *tailcals)
{
	enum generic_func_args_enum fgs_args;
	unsigned long a0, a1, a2, a3, a4;
	struct execve_map_value *enter;
	struct msg_generic_kprobe *e;
	int zero = 0;
	bool walker = 0;
	long ty, total;
	__u32 ppid;

	/* Preamble to setup context */
	enter = event_find_curr(&ppid, 0, &walker);
	if (!enter)
		return 0;

	e = map_lookup_elem(heap_map, &zero);
	if (!e)
		return 0;

	total = e->common.size;

	a0 = e->a0;
	a1 = e->a1;
	a2 = e->a2;
	a3 = e->a3;
	a4 = e->a4;

	ty = bpf_core_enum_value(fgs_args, arg1);
	if (total < MAX_TOTAL) {
		void *map = args1_filter_map;
		unsigned long a1m, arg_meta;
		long errv;

		a1m = bpf_core_enum_value(fgs_args, arg1m);
		arg_meta = get_arg_meta(a1m, a0, a1, a2, a3, a4);
		errv = read_call_arg(e->args, ty, total, a1, arg_meta, map, enter);
		if (errv < 0)
			return 0;
		total += errv;
	}
	e->common.size = total;
	tail_call(ctx, tailcals, 2);
	return 0;
}

static inline __attribute__((always_inline))
int generic_process_event2(
	void *ctx,
	struct bpf_map_def *heap_map,
	struct bpf_map_def *args2_filter_map,
	struct bpf_map_def *tailcals)
{
	enum generic_func_args_enum fgs_args;
	unsigned long a0, a1, a2, a3, a4;
	struct execve_map_value *enter;
	struct msg_generic_kprobe *e;
	int zero = 0;
	bool walker = 0;
	long ty, total;
	__u32 ppid;

	/* Preamble to setup context */
	enter = event_find_curr(&ppid, 0, &walker);
	if (!enter)
		return 0;

	e = map_lookup_elem(heap_map, &zero);
	if (!e)
		return 0;

	total = e->common.size;

	a0 = e->a0;
	a1 = e->a1;
	a2 = e->a2;
	a3 = e->a3;
	a4 = e->a4;

	ty = bpf_core_enum_value(fgs_args, arg2);
	if (total < MAX_TOTAL) {
		void *map = args2_filter_map;
		unsigned long a2m, arg_meta;
		long errv;

		a2m = bpf_core_enum_value(fgs_args, arg2m);
		arg_meta = get_arg_meta(a2m, a0, a1, a2, a3, a4);
		errv = read_call_arg(e->args, ty, total, a2, arg_meta, map, enter);
		if (errv < 0)
			return 0;
		total += errv;
	}
	e->common.size = total;
	tail_call(ctx, tailcals, 3);
	return 0;
}

static inline __attribute__((always_inline))
int generic_process_event3(
	void *ctx,
	struct bpf_map_def *heap_map,
	struct bpf_map_def *args3_filter_map,
	struct bpf_map_def *tailcals)

{
	enum generic_func_args_enum fgs_args;
	unsigned long a0, a1, a2, a3, a4;
	struct execve_map_value *enter;
	struct msg_generic_kprobe *e;
	int zero = 0;
	bool walker = 0;
	long ty, total;
	__u32 ppid;

	/* Preamble to setup context */
	enter = event_find_curr(&ppid, 0, &walker);
	if (!enter)
		return 0;

	e = map_lookup_elem(heap_map, &zero);
	if (!e)
		return 0;

	total = e->common.size;

	a0 = e->a0;
	a1 = e->a1;
	a2 = e->a2;
	a3 = e->a3;
	a4 = e->a4;

	/* Arg filter and copy logic */
	ty = bpf_core_enum_value(fgs_args, arg3);
	if (total < MAX_TOTAL) {
		void *map = args3_filter_map;
		unsigned long a3m, arg_meta;
		long errv;

		a3m = bpf_core_enum_value(fgs_args, arg3m);
		arg_meta = get_arg_meta(a3m, a0, a1, a2, a3, a4);
		errv = read_call_arg(e->args, ty, total, a3, arg_meta, map, enter);
		if (errv < 0)
			return 0;
		total += errv;
	}
	e->common.size = total;
	tail_call(ctx, tailcals, 4);
	return 0;
}

static inline __attribute__((always_inline))
int generic_process_event4(
	void *ctx,
	struct bpf_map_def *heap_map,
	struct bpf_map_def *args4_filter_map)
{
	enum generic_func_args_enum fgs_args;
	unsigned long a0, a1, a2, a3, a4;
	struct execve_map_value *enter;
	struct msg_generic_kprobe *e;
	int zero = 0;
	bool walker = 0;
	long ty, total;
	__u32 ppid;

	/* Preamble to setup context */
	enter = event_find_curr(&ppid, 0, &walker);
	if (!enter)
		return 0;

	e = map_lookup_elem(heap_map, &zero);
	if (!e)
		return 0;

	total = e->common.size;

	a0 = e->a0;
	a1 = e->a1;
	a2 = e->a2;
	a3 = e->a3;
	a4 = e->a4;

	ty = bpf_core_enum_value(fgs_args, arg4);
	if (total < MAX_TOTAL) {
		void *map = args4_filter_map;
		unsigned long a4m, arg_meta;
		long errv;

		a4m = bpf_core_enum_value(fgs_args, arg4m);
		arg_meta = get_arg_meta(a4m, a0, a1, a2, a3, a4);
		errv = read_call_arg(e->args, ty, total, a4, arg_meta, map, enter);
		if (errv < 0)
			return 0;
		total += errv;
	}
	e->common.size = total;

	/* Post event */
	total += sizeof(struct msg_common) + sizeof(struct msg_execve_key) + sizeof(__u64);
	/* Code movement from clang forces us to inline bounds checks here */
	asm volatile("%[total] &= 0x7fff;\n"
		"if %[total] < 9000 goto +1\n;"
		"%[total] = 9000;\n"
		: : [total] "+r"(total):);
	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, e, total);
	return 0;
}
