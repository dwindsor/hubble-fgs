#include "vmlinux.h"
#include "api.h"

#include "egress.h"

char _license[] __attribute__((section(("license")), used)) = "GPL";

__attribute__((section(("classifier/egress_tcp")), used)) int
event_tc_egress_tcp(struct __sk_buff *skb)
{
	bpf_parse_tls_egress(skb);
	return TC_ACT_UNSPEC;
}
