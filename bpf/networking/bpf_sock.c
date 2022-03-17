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
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

__attribute__((section(("cgroup/sock_create")), used)) int
sock_create(struct bpf_sock *ctx)
{
	u32 pid = get_current_pid_tgid(ctx) >> 32;
	u64 sock = get_socket_cookie(ctx);
	struct execve_map_value *value;

	if (ctx->type != SOCK_DGRAM && ctx->type != SOCK_STREAM)
		return 1;

	/* Ideally we would be able to bind the socket to create early,
	 * but its possible that we don't have an entry for the thread
	 * if its a child thread, etc. Perhaps we should always have
	 * entries, but we don't at the moment. So to ensure we don't
	 * mislead the next layer to process this we not only need to
	 * check if the entry exists but also that ktime!=0 which would
	 * indicate its a stale entry that we are preparing to GC.
	 */
	value = execve_map_get(pid);
	if (!value || value->key.ktime == 0) {
		struct execve_map_value v = { 0 };
		/* Error case, should not happen */
		map_update_elem(&socket_cookie_to_proc_map, &sock, &v, 0);
	} else {
		map_update_elem(&socket_cookie_to_proc_map, &sock, value, 0);
	}
	return 1;
}
