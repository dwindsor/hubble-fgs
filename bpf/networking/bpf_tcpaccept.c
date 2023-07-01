#include "vmlinux.h"

#include "api.h"
#include "bpf_event.h"
#include "bpf_task.h"
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
tg_event_tcp_acceptret(struct accept_args *ctx)
{
	return __event_tcp_acceptret(ctx);
}

__attribute__((section("tracepoint/syscalls/sys_exit_accept4"), used)) int
tg_event_tcp_accept4ret(struct accept_args *ctx)
{
	return __event_tcp_acceptret(ctx);
}
