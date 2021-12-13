#include "vmlinux.h"

#ifndef bpf_map_def
struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};
#endif

#define SOCK_CTX

#include "api.h"
#include "hubble_msg.h"
#include "bpf_events.h"
#include "cookie.h"

char _license[] __attribute__((section(("license")), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int  _version __attribute__((section(("version")), used)) = VMLINUX_KERNEL_VERSION;
#endif

__attribute__((section(("cgroup/sock_create")), used))
int sock_create(struct bpf_sock *ctx)
{
	u32 pid = get_current_pid_tgid(ctx) >> 32;
	u64 sock = get_socket_cookie(ctx);
	struct execve_map_value *value;

	if (ctx->type != SOCK_DGRAM && ctx->type != SOCK_STREAM)
		return 1;

	value = map_lookup_event(pid);
	if (!value) {
		struct execve_map_value v = {0};
		/* Error case, should not happen */
		map_update_elem(&socket_cookie_to_proc_map, &sock, &v, 0);
	} else {
		map_update_elem(&socket_cookie_to_proc_map, &sock, value, 0);
	}
	return 1;
}
