#ifndef bottle_h_INCLUDED
#define bottle_h_INCLUDED

#include "parser.h"

#define BOTTLE_DATA_SIZE 8192
#define BOTTLE_MASK(var) asm volatile ("%0 &= 0x1fff;\n": "+r"(var)::)

struct bottle {
	u32 len;

	/* Additional headroom for event headers. */
	u8 scratch[32];

	/* Note that this is twice as large as it needs to be in order
	 * to convince the verifier that it's safe to access. Bounds checks
	 * based on bottle->len are not sufficient.
	 */
	u8 data[BOTTLE_DATA_SIZE*2];
};

struct bpf_map_def __attribute__((section("maps"), used)) bottle_heap = {
       .type = BPF_MAP_TYPE_PERCPU_ARRAY,
       .key_size = sizeof(int),
       .value_size = sizeof(struct bottle),
       .max_entries = 1,

};

struct bpf_map_def __attribute__((section("maps"), used)) bottles = {
       .type = BPF_MAP_TYPE_LRU_HASH,
       .key_size = sizeof(struct msg_tls_ipv4),
       .value_size = sizeof(struct bottle),
       .max_entries = 1024,
};

static inline __attribute__((always_inline))
void *bottle_get_data(struct bottle *bottle, u32 off, u32 len)
{
	u32 bottle_len = bottle->len;
	BOTTLE_MASK(bottle_len);
	if (off + len > bottle_len) {
		return 0;
	}
	BOTTLE_MASK(off);
	return bottle->data + off;
}

static inline __attribute__((always_inline))
void bottle_drop(struct msg_tls_ipv4 *key)
{
	map_delete_elem(&bottles, key);
}

static inline __attribute__((always_inline))
struct bottle *bottle_fill(ctx_md *ctx, struct msg_tls_ipv4 *key,
				   int payload_off)
{
	struct bottle *bottle = map_lookup_elem(&bottles, key);

	if (!bottle) {
		int zero = 0;
		bottle = map_lookup_elem(&bottle_heap, &zero);
		if (!bottle)
			return 0;

		bottle->len = 0;

		if (map_update_elem(&bottles, key, bottle, 0))
			return 0;

		bottle = map_lookup_elem(&bottles, key);
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
	pkt_copy(bottle->data + bottle_len,
		 ctx->data_end,
		 ctx->data,
		 copy);
#else
	if (copy < 2) {
		/* FIXME verifier off-by-one bug(?), can't make it pass with "copy < 1":
		 *   invalid access to map value, value_size=8196 off=4 size=0
		 *   R3 min value is outside of the allowed memory range
		 * Working around this by doing a copy with constant len=1.
                 */
		if (copy == 1) {
			int err = skb_load_bytes(ctx, payload_off, bottle->data + bottle_len, 1);
			if (err)
				goto discard;
		} else {
			/* Nothing to copy, so this is an empty packet, e.g. a SYN etc. */
			return bottle;
		}
	} else {
		int err = skb_load_bytes(ctx, payload_off, bottle->data + bottle_len, copy);
		if (err) {
			goto discard;
		}
	}
#endif

	bottle->len += copy;

	return bottle;

discard:
	map_delete_elem(&bottles, key);
	return 0;
}


#endif // bottle_h_INCLUDED

