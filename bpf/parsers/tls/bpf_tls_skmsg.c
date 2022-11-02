#include "vmlinux.h"
#include "api.h"

#define SK_MSG

#include "egress.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

__attribute__((section("sk_msg/fgs_tls"), used)) int
bpf_tls_sk_msg_fgs(struct sk_msg_md *skmsg)
{
	__u64 *cookie;
	int zero = 0;

	cookie = map_lookup_elem(&tls_cookie_heap, &zero);
	if (!cookie)
		return SK_PASS;
	*cookie = (u64)skmsg->sk;
	if (!*cookie)
		return SK_PASS;

	bpf_parse_tls_egress(skmsg, cookie);
	return SK_PASS;
}
