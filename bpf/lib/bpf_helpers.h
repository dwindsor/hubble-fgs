#ifndef __BPF_HELPERS_
#define __BPF_HELPERS_

/* relax_verifier is a dummy helper call to introduce a pruning checkpoint
 * to help relax the verifier to avoid reaching complexity limits.
 */
static inline __attribute__((always_inline)) void relax_verifier(void)
{
       volatile int  __attribute__ ((__unused__)) id = get_smp_processor_id();
}
#endif
