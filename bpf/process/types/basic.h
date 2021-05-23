#include "operations.h"
#include "bpf_events.h"

/* Type IDs form API with user space generickprobe.go */
enum {
	filter = -2,
	nop = 0,
	int_type = 1,
	char_buf = 2,
	char_iovec = 3,
	size_type = 4,
	skb_type = 5,
	string_type = 6,

	s64_ty = 10,
	u64_ty = 11,
	s32_ty = 12,
	u32_ty = 13,

	filename_ty = 14,
	path_ty = 15,
	file_ty = 16,

	nop_s64_ty = -10,
	nop_u64_ty = -11,
	nop_u32_ty = -12,
	nop_s32_ty = -13,
};

enum {
	char_buf_enomem = -1,
	char_buf_pagefault = -2,
	char_buf_toolarge = -3,
};

struct skb_type {
	__u32 hash;
	__u32 len;
	__u32 priority;
	__u32 mark;
};

enum {
	ACTION_POST = 0,
};

struct selector_action {
	__u32 actionlen;
	__u32 act[];
};

struct selector_arg_filter {
	__u32 arglen;
	__u32 index;
	__u32 op;
	__u32 vallen;
	__u32 type;
	__u8  value;
} __attribute__((packed));

#define MAX_ARGS_SIZE 80
#define MAX_ARGS_ENTRIES 8
#define MAX_MATCH_VALUES 4
/* String parsing consumes instructions so this adds an additional
 * knob to tune how many instructions we should spend parsing
 * strings.
 */
#define MAX_MATCH_STRING_VALUES 2

/* Constants bounding printers if these change or buffer size changes then
 * we will need to resize. TBD would be to size these at compile time using
 * buffer size information.
 */
#define MAX_STRING 1024

static inline __attribute__((always_inline))
bool ty_is_nop(int ty) {
	switch (ty) {
		case nop:
		case nop_s64_ty:
		case nop_u64_ty:
		case nop_s32_ty:
		case nop_u32_ty:
		return true;

		default:
		return false;
	}
}

static inline __attribute__((always_inline))
int return_error(int *s, int err) {
	*s = err;
	return sizeof(int);
}

/* Error writer for use when pointer *s is lost to stack and can not
 * be recoved with known bounds. We had to push this via asm to stop
 * clang from omitting some checks and applying code motion on us.
 */
static inline __attribute__((always_inline))
int return_stack_error(char *args, int orig, int err)
{
	asm volatile("%[orig] &= 0xfff;\n"
		     "r1 = *(u64 *)%[args];\n"
		     "r1 += %[orig];\n"
		     "*(u32 *)(r1 + 0) = %[err];\n"
		     :: [orig] "r+" (orig), [args] "m+"(args), [err] "r+"(err): "r1");
	return sizeof(int);
}

static inline __attribute__((always_inline))
int parse_iovec_array(char *args, unsigned long arg, int i, __u64 off) {
	struct iovec iov; // limit is 1024 using a hack now. For 5.4 kernel we should loop over 1024
	char index = sizeof(struct iovec) * i;
	__u64 size;
	int err;

	err = probe_read(&iov, sizeof(iov), (struct iovec *)(arg+index));
	if (err < 0)
		return char_buf_pagefault;
	size = iov.iov_len;
	if (size > 4094)
		return char_buf_toolarge;
	asm volatile("%[off] &= 0xeff;\n"
		     "%[size] &= 0xeff;\n"
			:: [off] "+r"(off), [size] "+r"(size):);
	err = probe_read(&args[off], size, (char *) iov.iov_base);
	if (err < 0)
		return char_buf_pagefault;
	return iov.iov_len;
}

// for loop can not be unrolled which is needed for 4.19 kernels :(
#define PARSE_IOVEC_ENTRY { \
	int c;								\
	/* embedding this in the loop counter breaks verifier */ 	\
	if (i >= cnt)							\
		goto char_iovec_done;					\
	c = parse_iovec_array(args, arg, i, off);			\
	if (c < 0)							\
	       return return_stack_error(args, 0, c);			\
	size += c;							\
	c &= 0x7fff;							\
	off += c;							\
	i++;								\
}

// We parse a max iovec entries and any more can be detected in db
#define PARSE_IOVEC_ENTRIES { \
	PARSE_IOVEC_ENTRY     \
	PARSE_IOVEC_ENTRY     \
	PARSE_IOVEC_ENTRY     \
	PARSE_IOVEC_ENTRY     \
	PARSE_IOVEC_ENTRY     \
	PARSE_IOVEC_ENTRY     \
	PARSE_IOVEC_ENTRY     \
}

#define MAX_STRING_FILTER 128

static inline __attribute__((always_inline))
int cmpbytes(char *s1, char *s2, size_t n)
{
	int i;
#pragma unroll
	for (i = 0; i < MAX_STRING_FILTER; i++) {
		if (i < n && s1[i] != s2[i]) return -1;
	}

	return 0;
}

static inline __attribute__((always_inline))
long copy_path(char *args, unsigned long arg)
{
	int *s = (int *)args;
	struct path path;
	long size;

	probe_read(&path, sizeof(path), (void *)arg);
	size = getpath(&args[4], path, 0);
	*s = (__u32)size;
	if (size < 0)
		return filter;
	else if (size == 0)
		return 0;
	size += 4;
	return size;
}

static inline __attribute__((always_inline))
long copy_strings(char *args, unsigned long arg)
{
	int *s = (int *)args;
	long size;

	size = probe_read_str(&args[4], MAX_STRING, (char *)arg);
	if (size < 0) {
		return filter;
	}
	*s = size;
	// Initial 4 bytes hold string length
	return size + 4;
}

static inline __attribute__((always_inline))
long copy_skb(char *args, unsigned long arg)
{
	struct sk_buff *skb = (struct sk_buff *)arg;
	struct skb_type *skb_event = (struct skb_type *)args;

	probe_read(&skb_event->hash, sizeof(__u32), _(&skb->hash));
	probe_read(&skb_event->len, sizeof(__u32), _(&skb->len));
	probe_read(&skb_event->priority, sizeof(__u32), _(&skb->priority));
	probe_read(&skb_event->mark, sizeof(__u32), _(&skb->mark));
	return sizeof(struct skb_type);
}

static inline __attribute__((always_inline))
long copy_char_buf(char *args, unsigned long arg, unsigned long argm)
{
	int *s = (int *)args;
	size_t bytes = 0;
	int err;

	if (argm == -1) {
		u64 tid = get_current_pid_tgid();
		retprobe_map_set(tid, arg);
		return return_error(s, 0);
	}
	probe_read(&bytes, sizeof(bytes), &argm);

	/* Bound bytes <4095 to ensure bytes does not read past end of buffer */
	err = probe_read(&args[4], bytes&0xfff, (char *)arg);
	if (err < 0)
		return return_error(s, char_buf_pagefault);
	*s = (int)bytes;
	return bytes + 4;
}

static inline __attribute__((always_inline))
long filter_char_buf(struct selector_arg_filter *filter, char *args)
{
	char *value = (char *)&filter->value;
	long i, j = 0;

#pragma unroll
	for (i = 0; i < MAX_MATCH_STRING_VALUES; i++) {
		__u32 length;
		int err, v, a, postoff = 0;

		/* filter->vallen is pulled from user input so we also need to
		 * ensure its bounded.
		 */
		asm volatile("%[j] &= 0xff;\n" :: [j] "+r"(j):);
		length = *(__u32 *)&value[j];
		asm volatile("%[length] &= 0x3f;\n" :: [length] "+r"(length):);
		v = (int)value[j];
		a = (int)args[0];
		if (filter->op == op_filter_eq) {
			if (v != a)
				goto skip_string;
		} else if (filter->op == op_filter_str_postfix) {
			postoff = a - length;
			asm volatile("%[postoff] &= 0x3f;\n" :: [postoff] "+r"(postoff):);
		}

		/* This is redundant, but seems we lost 'j' bounds from
		 * above so at the moment its necessary until we improve
		 * compiler.
		 */
		asm volatile("%[j] &= 0xff;\n" :: [j] "+r"(j):);
		err = cmpbytes(&value[j+4], &args[4+postoff], length);
		if (!err)
			return 1;
skip_string:
		j += length + 4;
		if (j + 8 >= filter->vallen)
			break;
	}
	return 0;
}

static inline __attribute__((always_inline))
long copy_char_iovec(char *args, unsigned long arg, unsigned long argm)
{
	long size, off = 0;
	int err, i = 0, cnt, *s = (int *)&args[off];

	if (argm == -1) {
		u64 tid = get_current_pid_tgid();
		retprobe_map_set(tid, arg);
			return return_error(s, 0);
	}
	err = probe_read(&cnt, sizeof(cnt), &argm);
	if (err < 0) {
		return return_stack_error(args, 0, char_buf_pagefault);
	}

	size = 0;
	off += 4;
	PARSE_IOVEC_ENTRIES // may return an error directly
	/* PARSE_IOVEC_ENTRIES will jump here when done or return error */
char_iovec_done:
	s = (int *)args;
	*s = size;
	return size + 4;
}

static inline __attribute__((always_inline))
long filter_64ty(struct selector_arg_filter *filter, char *args)
{
	__u64 *v = (__u64 *)&filter->value;
	int i, j = 0;

#pragma unroll
	for (i = 0; i < MAX_MATCH_VALUES; i++) {
		__u64 w = v[i];
		bool res = (*(u64 *)args == w);

		if (filter->op == op_filter_eq && res)
			return 1;
		if (filter->op == op_filter_neq && !res)
			return 1;
		j += 8;
		if (j + 8 >= filter->vallen)
			break;
	}
	return 0;
}

static inline __attribute__((always_inline))
long filter_32ty(struct selector_arg_filter *filter, char *args)
{
	__u32 *v =  (__u32 *)&filter->value;
	int i, j = 0;

#pragma unroll
	for (i = 0; i < MAX_MATCH_VALUES; i++) {
		__u32 w = v[i];
		bool res = (*(u32 *)args == w);

		if (filter->op == op_filter_eq && res)
			return 1;
		if (filter->op == op_filter_neq && !res)
			return 1;
		// placed here to allow llvm unroll this loop
		j += 4;
		if (j + 8 >= filter->vallen)
			break;
	}
	return 0;
}

static inline __attribute__((always_inline))
size_t type_to_min_size(int type)
{
	switch (type) {
	case string_type:
		return MAX_STRING;
	case int_type:
	case s32_ty:
	case u32_ty:
		return 4;
	case skb_type:
		return sizeof(struct skb_type);
	case size_type:
	case s64_ty:
	case u64_ty:
		return 8;
	case char_buf:
	case char_iovec:
		return 4;
	// nop or something else we do not process here
	default:
		return 0;
	}
}

static inline __attribute__((always_inline))
int selector_arg_offset(__u8 *f,
			struct msg_generic_kprobe *e,
			__u32 selector)
{
	struct selector_arg_filter *filter;
	long seloff, argoff, pass;
	__u32 *tmp, len, index;
	char *args;

	selector *= 4;
	selector += 4;

	asm volatile (
	"if %[selector] > 68 goto +9;\n"
	"%[t] = %[m];\n"
	"%[t] += %[selector];\n"
	"%[selector] = *(u32 *)(%[t] + 0);\n"
	"if %[selector] > 1004 goto +5;\n"
	"%[t] = %[m];\n"
	"%[t] += %[selector];\n"
	"%[len] = *(u32 *)(%[t] + 8);\n" // pid header length;
	:[selector] "+r"(selector),
	  [len] "+r"(len),
          [m] "+r"(f),
	  [t] "+r"(tmp)
	::);

	/* seloff must leave space for verifier to walk strings
	 * so we set inside 4k maximum.
	 */
	seloff = selector + 8 + len;
	if (seloff > 3800) {
		return 0;
	}
	asm volatile("%[seloff] &= 0xeff;\n" :: [seloff] "+r"(seloff):);
	filter = (struct selector_arg_filter *)&f[seloff];

	if (filter->arglen <= 4) // no filters
		return seloff;

	index = filter->index;
	if (index > 5)
		return 0;

	asm volatile("%[index] &= 0x7;\n" :: [index] "+r"(index):);
	argoff = e->argsoff[index];
	asm volatile("%[argoff] &= 0xeff;\n" :: [argoff] "+r"(argoff):);
	args = &e->args[argoff];

	switch (filter->type) {
	case string_type:
	case char_buf:
		pass = filter_char_buf(filter, args);
		break;
	case s64_ty:
	case u64_ty:
		pass = filter_64ty(filter, args);
		break;
	case size_type:
	case int_type:
	case s32_ty:
	case u32_ty:
		pass = filter_32ty(filter, args);
		break;
	default:
		pass = 1; // no policy in place
		break;
	}

	return pass ? seloff : 0;
}

static inline __attribute__((always_inline))
int filter_args_reject(void) {
	u64 tid = get_current_pid_tgid();
	retprobe_map_clear(tid);
	return 0;
}

static inline __attribute__((always_inline))
int filter_args(struct msg_generic_kprobe *e,
		int index, void *filter_map)
{
	int zero = 0;
	__u8 *f;

	/* No filters and no selectors so just accepts */
	f = map_lookup_elem(filter_map, &zero);
	if (!f) {
		return 1;
	}

	/* No selectors, accept by default */
	if (!e->active[SELECTORS_ACTIVE]) {
		return 1;
	}

	/* We ran process filters early as a prefilter to drop unrelated
	 * events early. Now we need to ensure that active pid sselectors
	 * have their arg filters run.
	 */
	if (index > SELECTORS_ACTIVE)
		return filter_args_reject();

	if (e->active[index]) {
		int pass = selector_arg_offset(f, e, index);
		if (pass)
			return pass;
	}
	return 0;
}

#define MAX_SELECTORS 8

static inline __attribute__((always_inline))
long filter_read_arg(void *ctx, int index,
		     struct bpf_map_def *heap,
		     struct bpf_map_def *filter,
		     struct bpf_map_def *tailcalls)
{
	struct msg_generic_kprobe *e;
	int pass, zero = 0;
	bool postit = true;
	size_t total;

	e = map_lookup_elem(heap, &zero);
	if (!e)
		return 0;
	pass = filter_args(e, index, filter);
	if (!pass) {
		index++;
		if (index > MAX_SELECTORS || !e->active[index])
			return filter_args_reject();
		tail_call(ctx, tailcalls, index + 5);
		return 2;
	}

	// If pass >1 then we need to consult the selector actions
	// otherwise pass==1 indicates using default action. Pass=1
	// indicates no selectors were attached.
	if (pass > 1) {
		struct selector_arg_filter *arg;
		struct selector_action *actions;
		__u8 *f;
		int i;

		f = map_lookup_elem(filter, &zero);
		if (!f)
			goto dopost;

		arg = (struct selector_arg_filter *)&f[pass];
		actions = (struct selector_action *)&f[pass+arg->arglen];

		/* Expect no more than two actions. */
		if (actions->actionlen > 4 && actions->actionlen < 12) {
			for (i = 0; i + 4 < actions->actionlen; i+=4) {
				__u32 act = actions->act[i];

				switch (act) {
				case ACTION_POST:
					postit = true;
					break;
				default:
					goto dopost;
				}
			}
		}
	}
dopost:
	total = e->common.size + generic_kprobe_common_size();
	/* Code movement from clang forces us to inline bounds checks here */
	asm volatile("%[total] &= 0x7fff;\n"
		"if %[total] < 9000 goto +1\n;"
		"%[total] = 9000;\n"
		: : [total] "+r"(total):);
	if (postit)
		perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, e, total);
	return 1;
}

/**
 * Read a generic argument
 *
 * @args: destination buffer for the generic argument
 * @type: type of the argument
 * @off: offset of the argument within @args
 * @arg: argument location (generally, address of the argument)
 * @argm: argument metadata. The meaning of this depends on the @type. Some
 *        types use a -1 to designate saving @arg into the retprobe map
 * @filter_map:
 *
 * Returns the size of data appended to @args.
 */
static inline __attribute__((always_inline))
long read_call_arg(struct msg_generic_kprobe *e,
		  int index, int type, long orig_off,
		  unsigned long arg, unsigned long argm,
		  void *filter_map)
{
	size_t min_size = type_to_min_size(type);
	char *args = e->args;
	long size = -1;

	if (orig_off >= 4095 - min_size)
		return 0;
	asm volatile("%[orig_off] &= 0xfff;\n" :: [orig_off] "+r"(orig_off):);
	args += orig_off;

	/* Cache args offset for filter use later */
	e->argsoff[index] = orig_off;

	switch (type) {
	case file_ty:
		{
		struct file *file;
		probe_read(&file, sizeof(file), &arg);
		arg = (unsigned long)&file->f_path;
		}
		// fallthrough to copy_path
	case path_ty:
		size = copy_path(args, arg);
		break;
	case filename_ty:
		{
		struct filename *file;
		probe_read(&file, sizeof(file), &arg);
		probe_read(&arg, sizeof(arg), &file->name);
		}
               // fallthrough to copy_string
	case string_type:
		size = copy_strings(args, arg);
		break;
	case size_type:
	case s64_ty:
	case u64_ty:
		probe_read(args, sizeof(__u64), &arg);
		size = sizeof(__u64);
		break;
	/* Consolidate all the types to save instructions */
	case int_type:
	case s32_ty:
	case u32_ty:
		probe_read(args, sizeof(__u32), &arg);
		size = sizeof(__u32);
		break;
	case skb_type:
		size = copy_skb(args, arg);
		break;
	case char_buf:
		size = copy_char_buf(args, arg, argm);
		break;
	case char_iovec:
		size = copy_char_iovec(args, arg, argm);
		break;
	default:
		size = 0;
		break;
	}
	return size;
}

static inline __attribute__((always_inline))
unsigned long get_arg_meta(int meta,
			   unsigned long a0,
			   unsigned long a1,
			   unsigned long a2,
			   unsigned long a3,
			   unsigned long a4)
{
	switch (meta) {
	case -1: return -1; // tbd what if this collides, seems unlikely.
	case 1: return a0;
	case 2: return a1;
	case 3: return a2;
	case 4: return a3;
	case 5: return a4;
	}
	return 0;
}
