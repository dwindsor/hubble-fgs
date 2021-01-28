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

struct bpf_map_def __attribute__((section("maps"), used)) args0_filter_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = 80,
	.max_entries = 1,
};

/* Constants bounding printers if these change or buffer size changes then
 * we will need to resize. TBD would be to size these at compile time using
 * buffer size information.
 */
#define MAX_STRING 1024

static inline __attribute__((always_inline))
int read_call_arg(char *args, int type, long off, unsigned long arg, unsigned long argm, struct execve_map_value *proc)
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
		int *f, *s = (int *)&args[off];
		int value;

		probe_read(&value, sizeof(int), &arg);
		f = map_lookup_elem(&args0_filter_map, &zero);

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
		*s = value;
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
			*s = 0;
			return 4; // 4 is accounting for initial length int
		}
		probe_read(&bytes, sizeof(bytes), &argm);

		if (off < 4095) {
			int err;
			/* Ensure bytes does not read past end of buffer */
			bytes &= 0x7fff;   // required to create min bound
			if (bytes > 6000) {  // creates uppder bounds [0, 4000]
				*s = char_buf_toolarge;
				return 4;
			}
			err = probe_read(&args[off+4], bytes, (char *)arg);
			if (err) {
				*s = char_buf_pagefault;
				return 4;
			}
			size = bytes + 4;
			*s = (int)bytes;
		} else {
			*s = char_buf_enomem;
			return 4;
		}
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
