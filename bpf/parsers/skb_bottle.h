#ifndef skb_bottle_h_INCLUDED
#define skb_bottle_h_INCLUDED

#define BOTTLE_DATA_SIZE 8192
#define BOTTLE_MASK(var) asm volatile ("%0 &= 0x1fff;\n": [var] "+r"(var)::)

struct skb_bottle {
	u32 len;

	/* Additional headroom for event headers. */
	u8 scratch[32];

	/* Note that this is twice as large as it needs to be in order
	 * to convince the verifier that it's safe to access. Bounds checks
	 * based on bottle->len are not sufficient.
	 */
	u8 data[BOTTLE_DATA_SIZE*2];
};

struct bpf_map_def __attribute__((section("maps"), used)) skb_bottle_heap = {
       .type = BPF_MAP_TYPE_PERCPU_ARRAY,
       .key_size = sizeof(int),
       .value_size = sizeof(struct skb_bottle),
       .max_entries = 1,

};

struct bpf_map_def __attribute__((section("maps"), used)) skb_bottles = {
       .type = BPF_MAP_TYPE_LRU_HASH,
       .key_size = sizeof(struct msg_tls_ipv4),
       .value_size = sizeof(struct skb_bottle),
       .max_entries = 1024,
};

static inline __attribute__((always_inline))
struct skb_bottle *skb_bottle_fill(struct __sk_buff *skb, struct msg_tls_ipv4 *key,
				   int payload_off)
{
	struct skb_bottle *bottle = map_lookup_elem(&skb_bottles, key);
	int err;

	if (!bottle) {
		int zero = 0;
		bottle = map_lookup_elem(&skb_bottle_heap, &zero);
		if (!bottle)
			return 0;

		bottle->len = 0;

		if (map_update_elem(&skb_bottles, key, bottle, 0))
			return 0;

		bottle = map_lookup_elem(&skb_bottles, key);
		if (!bottle)
			return 0;
	}

	int copy = skb->len - payload_off;
	u32 bottle_len = bottle->len;

	/* The proper check to see if it would overflow the usable size. */
	if (bottle_len + copy > BOTTLE_DATA_SIZE)
		goto discard;

	/* Mask the length and copy to convince the verifier we won't overflow. */
	BOTTLE_MASK(bottle_len);
	BOTTLE_MASK(copy);

	if (copy < 2) {
		/* FIXME verifier off-by-one bug(?), can't make it pass with "copy < 1":
		 *   invalid access to map value, value_size=8196 off=4 size=0
		 *   R3 min value is outside of the allowed memory range
		 * Working around this by doing a copy with constant len=1.
                 */
		if (copy == 1) {
			err = skb_load_bytes(skb, payload_off, bottle->data + bottle_len, 1);
			if (err)
				goto discard;
		} else {
			/* Nothing to copy, so this is an empty packet, e.g. a SYN etc. */
			return bottle;
		}
	} else {
		err = skb_load_bytes(skb, payload_off, bottle->data + bottle_len, copy);
		if (err) {
			goto discard;
		}
	}

	bottle->len += copy;

	return bottle;

discard:
	map_delete_elem(&skb_bottles, key);
	return 0;
}

static inline __attribute__((always_inline))
void *skb_bottle_get_data(struct skb_bottle *bottle, u32 off, u32 len)
{
	u32 bottle_len = bottle->len;
	BOTTLE_MASK(bottle_len);

	if (off + len > bottle_len) {
		return 0;
	}

	BOTTLE_MASK(off);
	BOTTLE_MASK(len);

	return bottle->data + off;
}

#endif // skb_bottle_h_INCLUDED

