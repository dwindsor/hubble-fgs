#include "vmlinux.h"

#include "api.h"
#include "hubble_msg.h"
#include "bpf_events.h"
#include "cookie.h"
#include "bpf_tcpaccept.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

__attribute__((section("tracepoint/syscalls/sys_exit_accept"), used)) int
event_tcp4_acceptret56(struct accept_args *ctx)
{
	return __event_tcp4_acceptret(ctx, false);
}

__attribute__((section("tracepoint/syscalls/sys_exit_accept4"), used)) int
event_tcp4_accept4ret56(struct accept_args *ctx)
{
	return __event_tcp4_acceptret(ctx, false);
}
