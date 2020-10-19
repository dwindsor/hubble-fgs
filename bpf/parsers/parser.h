#include "api.h"

static inline __attribute__((always_inline))
#ifdef SK_MSG
void *get_data(struct sk_msg_md *ctx, int off, int needed)
{
	int err = msg_pull_data(ctx, 0, off + needed, 0);
#else
void *get_data(struct __sk_buff *ctx, int off, int needed)
{
	int err = skb_pull_data(ctx, off + needed);
#endif
	void *data_end, *data, *tmp;

	if (err)
		return 0;

	data_end = (void*)(long)ctx->data_end;
	data = (void*)(long)ctx->data;
	/* We need to advance the pointer to offset position and
	 * then compare the new ptr + needed bytes to ensure we
	 * haven't walked off the end of the pointer. But, order
	 * matters here. This will smash the range value on the
	 * packet and create a new ptrid. Consider,
	 *
	 * r3 = r2       // r2 is the data pkt pointer
	 * r3 += off     // oops r3 is a new pkt pointer because off is not
	 * r3 += needed  // required to be a const, so we have two pkts as
	 *               // far as verifier is concerned, r2 and r3
	 * if r3 > r1    // r1 is data_end so now r3 has a bounds, but r2
	 *               // does not share these bounds
	 * <--- snip --->
	 * derference r2 later and verifier will fail because
	 * we verified the bound on r3, but that is not the same
	 * pointer as r2. To fix get our order of ops correct,
	 *
	 * r2 += off     // off need not be constant here. If its
	 *               // not constant r2 will have a new pktid
	 * r3 = r2       // Now r3 is r2 from verifier side
	 * r3 += needed  // needed must be a fixed known constant, then
	 *               // r3 and r2 are still the same pktid
	 * if (r3 > r1)  // Now we have bounds on original r2 and r2!
	 */
	asm volatile (
		"if %[off] s< 2048 goto +1;\n"
		"%[off] = 0;\n"
		"if %[off] s>= 0 goto +1;\n"
		"%[off] = 0;\n"
		"%[data] += %[off];\n"
		"%[tmp] = %[data];\n"
		"%[tmp] += %[needed];\n"
		"if %[tmp] <= %[data_end] goto +1;\n"
		"%[data] = 0;\n"
		: [data] "+r"(data),
		  [tmp] "+r"(tmp),
		  [data_end] "+r"(data_end),
		  [off] "+r"(off),
		  [needed] "+r"(needed)
		::);

	return data;
}
