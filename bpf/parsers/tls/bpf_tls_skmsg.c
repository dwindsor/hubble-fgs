#include "vmlinux.h"
#include "api.h"

#define SK_MSG

#include "egress.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

__attribute__((section("sk_msg/fgs_tls"), used)) int
bpf_tls_sk_msg_fgs(struct sk_msg_md *skmsg)
{
	bpf_parse_tls_egress(skmsg);
	return SK_PASS;
}
