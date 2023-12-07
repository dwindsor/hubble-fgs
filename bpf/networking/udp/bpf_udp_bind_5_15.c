#include "vmlinux.h"

#include "api.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "../cookie.h"
#include "bpf_tracing.h"
#include "bpf_udp_bind.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

enum cgroup_bpf_attach_type {
	CGROUP_INET4_POST_BIND,
	CGROUP_INET6_POST_BIND
};

__attribute__((section("kprobe/__cgroup_bpf_run_filter_sk"), used)) int
tg_udp_bind_sock(struct pt_regs *ctx)
{
	int attach = PT_REGS_PARM2(ctx);

	if (attach == bpf_core_enum_value(enum cgroup_bpf_attach_type, CGROUP_INET4_POST_BIND)) {
		return __udp_bind_sock(ctx, false);
	} else if (attach == bpf_core_enum_value(enum cgroup_bpf_attach_type, CGROUP_INET6_POST_BIND)) {
		return __udp_bind_sock(ctx, true);
	}

	return 1;
}
