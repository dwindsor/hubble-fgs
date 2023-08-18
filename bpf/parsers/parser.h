#ifndef parser_h_INCLUDED
#define parser_h_INCLUDED

#include "api.h"
#include "netns.h"
#include "../lib/tlsmsg.h"
#include "../lib/httpmsg.h"
#include "../lib/address_family.h"

#ifdef SK_MSG
typedef struct sk_msg_md ctx_md;
#else
typedef struct __sk_buff ctx_md;
#endif

static inline __attribute__((always_inline)) void *get_data(ctx_md *ctx,
							    int off, int needed)
{
#ifdef SK_MSG
	int err = msg_pull_data(ctx, 0, off + needed, 0);
#else
	int err = skb_pull_data(ctx, off + needed);
#endif
	void *data_end, *data, *tmp;

	if (err < 0)
		return 0;

	data_end = (void *)(long)ctx->data_end;
	data = (void *)(long)ctx->data;
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
	asm volatile("if %[off] s< 2048 goto +1;\n"
		     "%[off] = 0;\n"
		     "if %[off] s>= 0 goto +1;\n"
		     "%[off] = 0;\n"
		     "%[data] += %[off];\n"
		     "%[tmp] = %[data];\n"
		     "%[needed] &= 0x7fffffff;\n"
		     "%[tmp] += %[needed];\n"
		     "if %[tmp] <= %[data_end] goto +1;\n"
		     "%[data] = 0;\n"
		     : [data] "+r"(data), [tmp] "+r"(tmp),
		       [data_end] "+r"(data_end), [off] "+r"(off),
		       [needed] "+r"(needed)::);

	return data;
}

#define COPY32B                            \
                                           \
	"if %[len] < 32 goto +14\n"        \
	"%[tmp] = %[ptr];\n"               \
	"%[tmp] += 32;\n"                  \
	"if %[tmp] > %[end] goto 1f;\n"    \
	"%[tmp] = *(u64 *)(%[ptr] +0);\n"  \
	"*(u64 *)(%[to] + 0) = %[tmp];\n"  \
	"%[tmp] = *(u64 *)(%[ptr] +8);\n"  \
	"*(u64 *)(%[to] + 8) = %[tmp];\n"  \
	"%[tmp] = *(u64 *)(%[ptr] +16);\n" \
	"*(u64 *)(%[to] + 16) = %[tmp];\n" \
	"%[tmp] = *(u64 *)(%[ptr] +24);\n" \
	"*(u64 *)(%[to] + 24) = %[tmp];\n" \
	"%[to] += 32;\n"                   \
	"%[ptr] += 32;\n"                  \
	"%[len] -= 32;\n"                  \
                                           \
	"if %[len] < 16 goto +10\n"        \
	"%[tmp] = %[ptr];\n"               \
	"%[tmp] += 16;\n"                  \
	"if %[tmp] > %[end] goto 1f\n"     \
	"%[tmp] = *(u64 *)(%[ptr] +0);\n"  \
	"*(u64 *)(%[to] + 0) = %[tmp];\n"  \
	"%[tmp] = *(u64 *)(%[ptr] +8);\n"  \
	"*(u64 *)(%[to] + 8) = %[tmp];\n"  \
	"%[to] += 16;\n"                   \
	"%[ptr] += 16;\n"                  \
	"%[len] -= 16;\n"                  \
                                           \
	"if %[len] < 8 goto +8\n"          \
	"%[tmp] = %[ptr];\n"               \
	"%[tmp] += 8;\n"                   \
	"if %[tmp] > %[end] goto 1f;\n"    \
	"%[tmp] = *(u64 *)(%[ptr] +0);\n"  \
	"*(u64 *)(%[to] + 0) = %[tmp];\n"  \
	"%[ptr] += 8;\n"                   \
	"%[to] += 8;\n"                    \
	"%[len] -= 8;\n"                   \
                                           \
	"if %[len] < 4 goto +8\n"          \
	"%[tmp] = %[ptr];\n"               \
	"%[tmp] += 4;\n"                   \
	"if %[tmp] > %[end] goto 1f;\n"    \
	"%[tmp] = *(u32 *)(%[ptr] +0);\n"  \
	"*(u32 *)(%[to] + 0) = %[tmp];\n"  \
	"%[to] += 4;\n"                    \
	"%[ptr] += 4;\n"                   \
	"%[len] -= 4;\n"                   \
                                           \
	"if %[len] < 3 goto +12;\n"        \
	"%[tmp] = %[ptr];\n"               \
	"%[tmp] += 3;\n"                   \
	"if %[tmp] > %[end] goto 1f;\n"    \
	"%[tmp] = *(u8 *)(%[ptr] +0);\n"   \
	"*(u8 *)(%[to] + 0) = %[tmp];\n"   \
	"%[tmp] = *(u8 *)(%[ptr] +1);\n"   \
	"*(u8 *)(%[to] + 1) = %[tmp];\n"   \
	"%[tmp] = *(u8 *)(%[ptr] +2);\n"   \
	"*(u8 *)(%[to] + 2) = %[tmp];\n"   \
	"%[to] += 3;\n"                    \
	"%[ptr] += 3;\n"                   \
	"%[len] -= 3;\n"                   \
                                           \
	"if %[len] < 2 goto +10;\n"        \
	"%[tmp] = %[ptr];\n"               \
	"%[tmp] += 2;\n"                   \
	"if %[tmp] > %[end] goto 1f;\n"    \
	"%[tmp] = *(u8 *)(%[ptr] +0);\n"   \
	"*(u8 *)(%[to] + 0) = %[tmp];\n"   \
	"%[tmp] = *(u8 *)(%[ptr] +1);\n"   \
	"*(u8 *)(%[to] + 1) = %[tmp];\n"   \
	"%[to] += 2;\n"                    \
	"%[ptr] += 2;\n"                   \
	"%[len] -= 2;\n"                   \
                                           \
	"if %[len] < 1 goto +8;\n"         \
	"%[tmp] = %[ptr];\n"               \
	"%[tmp] += 1;\n"                   \
	"if %[tmp] > %[end] goto 1f;\n"    \
	"%[tmp] = *(u8 *)(%[ptr] +0);\n"   \
	"*(u8 *)(%[to] + 0) = %[tmp];\n"   \
	"%[to] += 1;\n"                    \
	"%[ptr] += 1;\n"                   \
	"%[len] -= 1;\n"

#define COPY64B                            \
	"%[tmp] = *(u64 *)(%[ptr] +0);\n"  \
	"*(u64 *)(%[to] + 0) = %[tmp];\n"  \
	"%[tmp] = *(u64 *)(%[ptr] +8);\n"  \
	"*(u64 *)(%[to] + 8) = %[tmp];\n"  \
	"%[tmp] = *(u64 *)(%[ptr] +16);\n" \
	"*(u64 *)(%[to] + 16) = %[tmp];\n" \
	"%[tmp] = *(u64 *)(%[ptr] +24);\n" \
	"*(u64 *)(%[to] + 24) = %[tmp];\n" \
	"%[tmp] = *(u64 *)(%[ptr] +32);\n" \
	"*(u64 *)(%[to] + 32) = %[tmp];\n" \
	"%[tmp] = *(u64 *)(%[ptr] +40);\n" \
	"*(u64 *)(%[to] + 40) = %[tmp];\n" \
	"%[tmp] = *(u64 *)(%[ptr] +48);\n" \
	"*(u64 *)(%[to] + 48) = %[tmp];\n" \
	"%[tmp] = *(u64 *)(%[ptr] +56);\n" \
	"*(u64 *)(%[to] + 56) = %[tmp];\n" \
	"%[to] += 64;\n"                   \
	"%[ptr] += 64;\n"                  \
	"%[len] -= 64;\n"

#define COPY256B \
	COPY64B  \
	COPY64B  \
	COPY64B  \
	COPY64B

#define COPY1024B \
	COPY256B  \
	COPY256B  \
	COPY256B  \
	COPY256B

static inline __attribute__((always_inline)) int
stack_pkt_copy(__u8 *to, __u8 *end, __u8 *from, __u32 copy)
{
	int len = copy, off = 0;
	uint64_t tmp, ptr;

	asm volatile("%[len] &= 0xff;\n"
		     "%[off] &= 0xff;\n"
		     "%[ptr] = %[from];\n" COPY32B "1:;\n"
		     : [tmp] "+r"(tmp), [ptr] "+r"(ptr), [off] "+r"(off),
		       [len] "+r"(len), [to] "+r"(to), [end] "+r"(end)
		     : [from] "r"(from)
		     :);
	return copy - len;
}

static inline __attribute__((always_inline)) int
small_pkt_copy(__u8 *to, __u8 *end, __u8 *from, __u32 copy)
{
	int len = copy, off = 0;
	uint64_t tmp, ptr;

	asm volatile("%[len] &= 0xfff;\n"
		     "%[off] &= 0xfff;\n"
		     "%[ptr] = %[from];\n"
		     // Default abort case
		     "if %[len] > 96 goto 1f;\n"
		     // 64B case
		     "if %[len] < 64 goto 2f;\n"
		     "%[tmp] = %[ptr];\n"
		     "%[tmp] += 64;\n"
		     "if %[tmp] > %[end] goto 2f;\n" COPY64B "2:\n"
		     // 32B case
		     COPY32B "1:;\n"
		     : [tmp] "+r"(tmp), [ptr] "+r"(ptr), [off] "+r"(off),
		       [len] "+r"(len), [to] "+r"(to), [end] "+r"(end)
		     : [from] "r"(from)
		     :);
	if (copy > 64)
		copy = 64;
	return copy - len;
}

static inline __attribute__((always_inline)) int
pkt_copy(__u8 *to, __u8 *end, __u8 *from, __u64 copy)
{
	int len = copy, off = 0;
	uint64_t tmp, ptr;

	asm volatile(
		"%[off] &= 0xfff;\n"
		"%[ptr] = %[from];\n"
#ifdef SK_SKB
		// 2048B case
		"if %[len] < 1024 goto 7f;\n"
		"%[tmp] = %[ptr];\n"
		"%[tmp] += 1024;\n"
		"if %[tmp] > %[end] goto 7f;\n" COPY256B COPY256B COPY256B
			COPY256B "7:\n"
#endif
		// 1024B case
		"if %[len] < 1024 goto 6f;\n"
		"%[tmp] = %[ptr];\n"
		"%[tmp] += 1024;\n"
		"if %[tmp] > %[end] goto 6f;\n" COPY256B COPY256B COPY256B
			COPY256B "6:\n"
		// 512B case
		"if %[len] < 512 goto 5f;\n"
		"%[tmp] = %[ptr];\n"
		"%[tmp] += 512;\n"
		"if %[tmp] > %[end] goto 5f;\n" COPY256B COPY256B "5:\n"
		// 256B case
		"if %[len] < 256 goto 4f;\n"
		"%[tmp] = %[ptr];\n"
		"%[tmp] += 256;\n"
		"if %[tmp] > %[end] goto 4f;\n" COPY64B COPY64B COPY64B COPY64B
		"4:;\n"
		// 128B case
		"if %[len] < 128 goto 3f;\n"
		"%[tmp] = %[ptr];\n"
		"%[tmp] += 128;\n"
		"if %[tmp] > %[end] goto 3f;\n" COPY64B COPY64B "3:;\n"
		// 64B case
		"if %[len] < 64 goto 2f\n"
		"%[tmp] = %[ptr];\n"
		"%[tmp] += 64;\n"
		"if %[tmp] > %[end] goto 2f;\n" COPY64B "2:\n"
		// 32B case
		COPY32B "1:;\n"
		: [tmp] "+r"(tmp), [ptr] "+r"(ptr), [off] "+r"(off),
		  [len] "+r"(len), [to] "+r"(to), [end] "+r"(end)
		: [from] "r"(from)
		:);
	return copy - len;
}

struct pkt_data {
	char data[16384];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct pkt_data);
	__uint(max_entries, 1);
} pkt_heap SEC(".maps");

/* Large context copy to copy packet payload when we need a prune point to
 * avoid complexity and insn count overrun even with 1mil insns.
 */
static inline int large_ctx_copy(ctx_md *ctx, __u64 next, __u64 offset,
				 __u64 copy)
{
	void *data, *data_end;
	int zero = 0;
	__u8 *to;

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	/* Bound our inputs to "good" values */
	asm volatile("%[next] &= 0x1fff;\n"
		     : [next] "+r"(next)::);
	asm volatile("%[copy] &= 0x1fff;\n"
		     : [copy] "+r"(copy)::);

	if ((data + next + copy) > data_end) {
		asm volatile("%[copy] &= 0x1fff;\n"
			     : [copy] "+r"(copy)::);
		data = get_data(ctx, next, copy);
		if (!data)
			return 0;
		data_end = (void *)(long)ctx->data_end;
	} else {
		data = data + next;
	}

	/* Duplicate map lookups because passing pointer through func
	 * call is not currently supported.
	 *
	 * TBD: JF, extend verifier to understand pointers/struct args.
	 */
	to = map_lookup_elem(&pkt_heap, &zero);
	if (!to)
		return 0;

	if (offset > 4096 - 32)
		return 0;

	to = to + offset;
	return pkt_copy(to, data_end, data, copy);
}

#ifdef SK_MSG

static inline __attribute__((always_inline)) void
msg_tls_tuple(struct sk_msg_md *msg, struct msg_tls_ip *tuple)
{
	if (msg->family == AF_INET) {
		tuple->daddr[0] = msg->remote_ip4;
		tuple->saddr[0] = msg->local_ip4;
		tuple->ipv6 = 0;
	} else if (msg->family == AF_INET6) {
		probe_read_kernel(&tuple->daddr, sizeof(tuple->daddr),
				  _(&(msg->remote_ip6)));
		probe_read_kernel(&tuple->saddr, sizeof(tuple->saddr),
				  _(&(msg->local_ip6)));
		tuple->ipv6 = 1;
	} else {
		return;
	}
	/* Compiler generated code verifier could not pass with if/else
	 * construct so we just reset {s|d}port for now.
	 */
	tuple->dport = 0;
	tuple->sport = msg->local_port;
	tuple->dport = msg->sk->dst_port;
	tuple->sport = msg->sk->src_port;

	if (is_tuple_local(tuple))
		tuple->uid = msg_netns(msg);
	tuple->remaining = HTTP_SEND;
}

#endif

#endif /* parser_h_INCLUDED */
