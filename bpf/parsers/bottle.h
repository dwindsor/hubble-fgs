// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef bottle_h_INCLUDED
#define bottle_h_INCLUDED

#include "parser.h"

#define BOTTLE_DATA_SIZE 8192
#define BOTTLE_MASK(var) asm volatile("%0 &= 0x1fff;\n" \
				      : "+r"(var)::)

struct bottle {
	u32 len;

	/* Additional headroom for event headers. */
	u8 scratch[32];

	/* Note that this is twice as large as it needs to be in order
	 * to convince the verifier that it's safe to access. Bounds checks
	 * based on bottle->len are not sufficient.
	 */
	u8 data[BOTTLE_DATA_SIZE * 2];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct bottle);
	__uint(max_entries, 1);
} tg_bottle_heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, __u64);
	__type(value, struct bottle);
	__uint(max_entries, 1024);
} tg_bottles SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __s32);
	__type(value, __s64);
	__uint(max_entries, 1);
} tg_bottle_map_stats SEC(".maps");

static inline __attribute__((always_inline)) void *
bottle_get_data(struct bottle *bottle, u32 off, u32 len)
{
	u32 bottle_len = bottle->len;
	BOTTLE_MASK(bottle_len);
	/* Avoid integer overflow checking if off + len > bottle_len */
	if ((off > bottle_len) || (len > (bottle_len - off))) {
		return 0;
	}
	BOTTLE_MASK(off);
	return bottle->data + off;
}

static inline __attribute__((always_inline)) void bottle_drop(u64 *cookie)
{
	int err = map_delete_elem(&tg_bottles, cookie);
	int zero = 0;
	s64 *cntr;
	if (!err && (cntr = map_lookup_elem(&tg_bottle_map_stats, &zero)))
		*cntr = *cntr - 1;
}

static inline __attribute__((always_inline)) struct bottle *
bottle_fill(ctx_md *ctx, u64 *cookie, int payload_off)
{
	struct bottle *bottle = map_lookup_elem(&tg_bottles, cookie);

	if (!bottle) {
		int zero = 0;
		int err;

		bottle = map_lookup_elem(&tg_bottle_heap, &zero);
		if (!bottle)
			return 0;

		bottle->len = 0;

		err = map_update_elem(&tg_bottles, cookie, bottle, 0);
		if (err) {
			return 0;
		} else {
			s64 *cntr = map_lookup_elem(&tg_bottle_map_stats, &zero);
			if (cntr)
				*cntr = *cntr + 1;
		}

		bottle = map_lookup_elem(&tg_bottles, cookie);
		if (!bottle)
			return 0;
	}

#ifdef SK_MSG
	int copy = ctx->size - payload_off;

	/* Linearize the message */
	if (msg_pull_data(ctx, payload_off, ctx->size, 0)) {
		goto discard;
	}
#else
	int copy = ctx->len - payload_off;
#endif

	u32 bottle_len = bottle->len;

	/* The proper check to see if it would overflow the usable size. */
	if (bottle_len + copy > BOTTLE_DATA_SIZE)
		goto discard;

	/* Mask the length and copy to convince the verifier we won't overflow. */
	BOTTLE_MASK(bottle_len);
	BOTTLE_MASK(copy);

#ifdef SK_MSG
	pkt_copy(bottle->data + bottle_len, ctx->data_end, ctx->data, copy);
#else
	if (copy < 2) {
		/* FIXME verifier off-by-one bug(?), can't make it pass with "copy < 1":
		 *   invalid access to map value, value_size=8196 off=4 size=0
		 *   R3 min value is outside of the allowed memory range
		 * Working around this by doing a copy with constant len=1.
                 */
		if (copy == 1) {
			int err = skb_load_bytes(ctx, payload_off,
						 bottle->data + bottle_len, 1);
			if (err)
				goto discard;
		} else {
			/* Nothing to copy, so this is an empty packet, e.g. a SYN etc. */
			return bottle;
		}
	} else {
		int err = skb_load_bytes(ctx, payload_off,
					 bottle->data + bottle_len, copy);
		if (err) {
			goto discard;
		}
	}
#endif

	bottle->len += copy;

	return bottle;

discard:
	map_delete_elem(&tg_bottles, cookie);
	return 0;
}

#endif // bottle_h_INCLUDED
