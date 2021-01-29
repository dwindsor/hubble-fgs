#include "operations.h"

/* Type IDs form API with user space generickprobe.go */
enum {
	filter = -2,
	nop = -1,
	string_type = 1,
	int_type = 2,
	skb_type = 3,
	size_type = 4,
	char_buf = 5,
	char_iovec = 6,
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
int return_error(int *s, int err) {
	*s = err;
	return sizeof(int);
}


static inline __attribute__((always_inline))
int parse_iovec_array(char *args, unsigned long arg, int i, int off) {
	struct iovec iov; // limit is 1024 using a hack now. For 5.4 kernel we should loop over 1024
	char index = sizeof(struct iovec) * i;
	int err;

	err = probe_read(&iov, sizeof(iov), (struct iovec *)(arg+index));
	if (err)
		return char_buf_pagefault;
	iov.iov_len &= 0x7fff;
	if (iov.iov_len > 4000)
		return char_buf_toolarge;
	off &= 0xFFF;
	err = probe_read(&args[off], iov.iov_len, (char *) iov.iov_base);
	if (err)
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
	       return return_error(s, c);				\
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
	PARSE_IOVEC_ENTRY     \
}

static inline __attribute__((always_inline))
int read_call_arg(char *args,
		  int type, long off,
		  unsigned long arg, unsigned long argm,
		  void *filter_map,
		  struct execve_map_value *proc)
{
	int size = -1;
	int zero = 0;

	if (type == nop) {
		size = 0;
	} else if (type == string_type && MAX_STRING + off < 4095) {
		int *s = (int *)&args[off];
		size = probe_read_str(&args[off+4], MAX_STRING, (char *)arg);
		*s = size;
		size += 4; // accounting for initial length int
	} else if (type == size_type && sizeof(size_t) + off < 4095) {
		probe_read(&args[off], sizeof(size_t), &arg);
		size = sizeof(size_t);
	} else if (type == int_type && sizeof(int) + off < 4095) {
		int *f;
		int value;

		probe_read(&value, sizeof(int), &arg);
		args[off] = value;

		f = map_lookup_elem(filter_map, &zero);
		if (f && *f) {
			int i;

			/* Ideally we would walk only count entries, but verifier
			 * and llvm plot to not allow this. Either clang refuses
			 * to unroll loops (too complex?) or verifier loses 'off'
			 * var and complains later in next arg handler.
			 *
			 * TBD fix clang/verifier and coconspirators.
			 */
#pragma unroll
			for (i = 1; i < MAX_ARGS_ENTRIES*2; i+=2) {
				int op = f[i];
				int v = f[i+1];

				if (op == op_filter_eq  && v == value)
					goto accept_filter;
				if (op == op_filter_lt && v < value)
					goto accept_filter;
				if (op == op_filter_gt && v > value)
					goto accept_filter;
			}
			return filter;
		}
accept_filter:
		size  = sizeof(int);
	} else if (type == skb_type && sizeof(struct skb_type) + off < 4095) {
		struct sk_buff *skb = (struct sk_buff *)arg;
		struct skb_type *skb_event = (struct skb_type *)&args[off];

		probe_read(&skb_event->hash, sizeof(__u32), _(&skb->hash));
		probe_read(&skb_event->len, sizeof(__u32), _(&skb->len));
		probe_read(&skb_event->priority, sizeof(__u32), _(&skb->priority));
		probe_read(&skb_event->mark, sizeof(__u32), _(&skb->mark));
		size = sizeof(struct skb_type);
	} else if (type == char_buf) {
		int *s = (int *)&args[off];
		size_t bytes = 0;

		if (argm == -1) {
			proc->retprobe_buffer = arg;
			return return_error(s, 0);
		}
		probe_read(&bytes, sizeof(bytes), &argm);

		if (off < 4095) {
			int err;
			/* Ensure bytes does not read past end of buffer */
			bytes &= 0x7fff;   // required to create min bound
			if (bytes > 6000)  // creates uppder bounds [0, 4000]
				return return_error(s, char_buf_toolarge);
			err = probe_read(&args[off+4], bytes, (char *)arg);
			if (err)
				return return_error(s, char_buf_pagefault);
			size = bytes + 4;
			*s = (int)bytes;
		} else {
			return return_error(s, char_buf_enomem);
		}
	} else if (type == char_iovec) {
		int err, i = 0, cnt, *s = (int *)&args[off];

		if (argm == -1) {
			proc->retprobe_buffer = arg;
			return return_error(s, 0);
		}
		err = probe_read(&cnt, sizeof(cnt), &argm);
		if (err) {
			return return_error(s, char_buf_pagefault);
		}

		size = 0;
		off += 4;
		PARSE_IOVEC_ENTRIES // may return an error directly
		/* PARSE_IOVEC_ENTRIES will jump here when done or return error */
char_iovec_done:
		/* This could be a buggy size_t -> int conversion except
		 * we bounded about with 0x7fff so should be good.
		 */
		*s = size;
		size += 4;
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
