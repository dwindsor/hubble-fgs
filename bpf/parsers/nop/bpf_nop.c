#include "vmlinux.h"
#include "api.h"

__attribute__((section(("sk_msg/fgs")), used)) int
bpf_nop_sk_msg_fgs(struct sk_msg_md *msg)
{
	return SK_PASS;
}
