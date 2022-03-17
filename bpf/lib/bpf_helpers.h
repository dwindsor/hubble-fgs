#ifndef __BPF_HELPERS_
#define __BPF_HELPERS_

#ifndef __READ_ONCE
#define __READ_ONCE(x) (*(volatile typeof(x) *)&x)
#endif
#ifndef __WRITE_ONCE
#define __WRITE_ONCE(x, v) (*(volatile typeof(x) *)&x) = (v)
#endif

#ifndef READ_ONCE
#define READ_ONCE(x)                                                           \
	({                                                                     \
		typeof(x) __val;                                               \
		__val = __READ_ONCE(x);                                        \
		compiler_barrier();                                            \
		__val;                                                         \
	})
#endif
#ifndef WRITE_ONCE
#define WRITE_ONCE(x, v)                                                       \
	({                                                                     \
		typeof(x) __val = (v);                                         \
		__WRITE_ONCE(x, __val);                                        \
		compiler_barrier();                                            \
		__val;                                                         \
	})
#endif

/* relax_verifier is a dummy helper call to introduce a pruning checkpoint
 * to help relax the verifier to avoid reaching complexity limits.
 */
static inline __attribute__((always_inline)) void relax_verifier(void)
{
	volatile int __attribute__((__unused__)) id = get_smp_processor_id();
}
#endif
