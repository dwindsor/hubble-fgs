#include "operations.h"

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


#define MAX_ARGS_SIZE 80
#define MAX_ARGS_ENTRIES 8

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

/* Error writer  for use when pointer *s is lost to stack and can not
 * be recoved with known bounds.
 */
static inline __attribute__((always_inline))
int return_stack_error(char *args, int orig, int err)
{
	asm volatile("%[orig] &= 0xfff;\n"
		     "r1 = *(u64 *)%[args];\n"
		     "r1 += %[orig];\n"
		     "*(u32 *)(r1 + 0) = %[err];\n"
		     :: [orig] "r+" (orig), [args] "m+"(args), [err] "r+"(err): "r1");
	//s = (int *)&args[o];
	//*s = err;
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

struct selector_arg_filter {
	__u32 arglen;
	__u32 index;
	__u32 op;
	__u32 vallen;
	__u32 type;
	__u8  value;
} __attribute__((packed));

static inline __attribute__((always_inline))
int selector_arg_offset(__u8 *f, char *args, __u32 arg, __u32 index)
{
	struct selector_arg_filter *filter;
	__u32 *tmp, len, off;

	index *= 4;
	index += 4;

	asm volatile (
	"if %[index] > 68 goto +9;\n"
	"%[t] = %[m];\n"
	"%[t] += %[index];\n"
	"%[index] = *(u32 *)(%[t] + 0);\n"
	"if %[index] > 1004 goto +5;\n"
	"%[t] = %[m];\n"
	"%[t] += %[index];\n"
	"%[len] = *(u32 *)(%[t] + 8);\n" // pid header length;
	:[index] "+r"(index),
	  [len] "+r"(len),
          [m] "+r"(f),
	  [t] "+r"(tmp)
	::);

	off = index + 8 + len;
	if (off > 4000) {
		return 0;
	}
	asm volatile("%[off] &= 0xeff;\n" :: [off] "+r"(off):);

	filter = (struct selector_arg_filter *)&f[off];
	if (filter->index != arg) {
		/* offset by 8 because we want to point arglen at previous entry
		 * to get correct {index,op,vallen,type,value} tuple.
		 */
		off += filter->vallen + 8;
		asm volatile("%[off] &= 0xeff;\n" :: [off] "+r"(off):);
		filter = (struct selector_arg_filter *)&f[off];
		if (filter->index != arg)
			return 1;
	}

	switch (filter->type) {
	case string_type:
	case char_buf:
		{
		char *value = (char *)&filter->value;
		__u32 length = *(__u32 *)&value[0];
		int err;
		int v, a;

		asm volatile("%[length] &= 0x3f;\n" :: [length] "+r"(length):);
		v = (int)value[0];
		a = (int)args[0];
		if (filter->op == op_filter_eq) {
			if (v != a)
				break;
		}
		err = cmpbytes(&value[4], &args[4], length);
		if (!err)
			return 1;
		}
		break;
	case s64_ty:
	case u64_ty:
		{
		__u8 *v = &filter->value;
		__u64 w = *(u64*)v;

		if (*(u64 *)args == w)
			return 1;
		}
		break;
	case size_type:
	case int_type:
	case s32_ty:
	case u32_ty:
#if 0
				if (op == op_filter_eq  && val == fval)
					goto accept_filter_u64;
				if (op == op_filter_lt && val < fval)
					goto accept_filter_u64;
				if (op == op_filter_gt && val > fval)
					goto accept_filter_u64;
#endif

		if (*(u32 *)args == filter->value)
			return 1;
		break;
	default:
		return 1; // no policy in place
	}

	return 0;
}

static inline __attribute__((always_inline))
int filter_arg(struct msg_generic_kprobe *e, int index, int type, char *args, void *filter_map)
{
	int pass, zero = 0;
	__u8 *f;

	/* No filters and no selectors so just accepts */
	f = map_lookup_elem(filter_map, &zero);
	if (!f) {
		return 1;
	}

	/* No selectors, accept */
	if (!e->s0 && !e->s1 && !e->s2 && !e->s3 && !e->s4 &&
	    !e->s5 && !e->s6 && !e->s7)
		return 1;

	/* We ran process filters early as a prefilter to drop unrelated
	 * events early. Now we need to ensure that active pid sselectors
	 * have their arg filters run.
	 */
	if (e->s0) {
		pass = selector_arg_offset(f, args, index, 0);
		if (pass)
			return 1;
	}
	if (e->s1) {
		pass = selector_arg_offset(f, args, index, 1);
		if (pass)
			return 1;
	}
	if (e->s2) {
		pass = selector_arg_offset(f, args, index, 2);
		if (pass)
			return 1;
	}
	if (e->s3) {
		pass = selector_arg_offset(f, args, index, 3);
		if (pass)
			return 1;
	}
	if (e->s4) {
		pass = selector_arg_offset(f, args, index, 4);
		if (pass)
			return 1;
	}
	if (e->s5) {
		pass = selector_arg_offset(f, args, index, 5);
		if (pass)
			return 1;
	}
	if (e->s6) {
		pass = selector_arg_offset(f, args, index, 6);
		if (pass)
			return 1;
	}
	if (e->s7) {
		pass = selector_arg_offset(f, args, index, 7);
		if (pass)
			return 1;
	}
	return 0;
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
	int pass;

	if (orig_off >= 4095 - min_size)
		return 0;
	asm volatile("%[orig_off] &= 0xfff;\n" :: [orig_off] "+r"(orig_off):);
	args += orig_off;

	switch (type) {
	case string_type:
		size = copy_strings(args, arg);
		break;
	case size_type:
		probe_read(args, sizeof(size_t), &arg);
		size = sizeof(size_t);
		break;
	case s64_ty:
	case u64_ty:
		probe_read(args, sizeof(__u64), &arg);
		size = sizeof(__u64);
		break;
	case s32_ty:
	case u32_ty:
		probe_read(args, sizeof(__u32), &arg);
		size = sizeof(__u32);
		break;
	case int_type:
		probe_read(args, sizeof(int), &arg);
		size  = sizeof(int);
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
	if (size < 0)
		return size;

	pass = filter_arg(e, index, type, args, filter_map);
	if (!pass)
		return -1;

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
