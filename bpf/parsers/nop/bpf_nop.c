#include "vmlinux.h"
#include "api.h"

__attribute__((section("sk_msg/fgsnop"), used)) int
tg_nop_sk_msg_fgs(struct sk_msg_md *msg)
{
	return SK_PASS;
}
