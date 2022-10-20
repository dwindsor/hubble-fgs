#include "vmlinux.h"

#include "api.h"
#include "hubble_msg.h"
#include "../parsers/tls/tls_map.h"
#include "../parsers/bottle.h"
#include "../parsers/http/http.h"
#include "bpf_events.h"
#include "cookie.h"
#include "bpf_network_helpers.h"
#include "netns.h"
#include "bpf_tcpaccept.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

__attribute__((section("tracepoint/syscalls/sys_exit_accept"), used)) int
event_tcp_acceptret_protocolshift(struct accept_args *ctx)
{
	return __event_tcp_acceptret(ctx, true);
}

__attribute__((section("tracepoint/syscalls/sys_exit_accept4"), used)) int
event_tcp_accept4ret_protocolshift(struct accept_args *ctx)
{
	return __event_tcp_acceptret(ctx, true);
}
