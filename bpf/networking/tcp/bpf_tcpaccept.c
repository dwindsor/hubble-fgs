#include "vmlinux.h"

#include "api.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "../cookie.h"
#include "../bpf_network_helpers.h"
#include "netns.h"
#include "bpf_tcpaccept.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

__attribute__((section("kprobe/tcp_create_openreq_child"), used)) int
tg_event_tcp_accept(struct pt_regs *ctx)
{
	return __event_tcp_accept(ctx);
}

__attribute__((section("kretprobe/tcp_create_openreq_child"), used)) int
tg_event_tcp_accept_ret(struct pt_regs *ctx)
{
	return __event_tcp_accept_ret(ctx);
}
