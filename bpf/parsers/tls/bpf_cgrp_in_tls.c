#include "vmlinux.h"
#include "api.h"

#include "bpf_event.h"
#include "bpf_task.h"
#include "bpf_sockops.h"
#include "parser.h"
#include "tls_map.h"

#define TLS_TYPE_HELLO 22
#define TLS_TYPE_DONE  0xff

// hook: ./net/ipv4/tcp_ipv4.c tcp_filter()
__attribute__((section("cgroup_skb/ingress"), used)) int
bpf_cgroup_skb_ingress_tls(struct __sk_buff *skb)
{
	struct msg_tls *event;
	int zero = 0;
	u64 *cookie;

	cookie = map_lookup_elem(&tls_cookie_heap, &zero);
	if (!cookie)
		return 1;
	*cookie = (u64)skb->sk;
	if (!*cookie)
		return;

	event = map_lookup_elem(&tls_map, cookie);
	if (event && event->type == TLS_TYPE_HELLO)
		bpf_parse_tls_skb(skb, event);
	return 1;
}
