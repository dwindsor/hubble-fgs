#include "vmlinux.h"

#include "api.h"
#include "hubble_msg.h"
#include "bpf_events.h"
#include "bpf_udp.h"
#include "cookie.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

__attribute__((section("cgroup/sock_create"), used)) int
sock_create(struct bpf_sock *ctx)
{
	u32 pid = get_current_pid_tgid(ctx) >> 32;
	u64 sock = get_socket_cookie(ctx);
	struct execve_map_value *value;
	struct socketmap_value process = { 0 };

	/* We only want to create UDP sockets here as TCP sockets are
	 * created by calls to listen and accept.
	 */
	if (ctx->type != SOCK_DGRAM)
		return 1;

	if (!sock) {
		emit_ip_error_event(ctx, 0, 0, false,
				    IP_ERROR_SOCK_CREATE_NO_COOKIE);
		return 1;
	}

	/* Ideally we would be able to bind the socket to create early,
	 * but its possible that we don't have an entry for the thread
	 * if its a child thread, etc. Perhaps we should always have
	 * entries, but we don't at the moment. So to ensure we don't
	 * mislead the next layer to process this we not only need to
	 * check if the entry exists but also that ktime!=0 which would
	 * indicate its a stale entry that we are preparing to GC.
	 */
	value = execve_map_get_noinit(pid);
	if (value && value->key.ktime) {
		process.key.pid = value->key.pid;
		process.key.ktime = value->key.ktime;
	}
	process.create_time = ktime_get_ns();
	add_socketmap(&sock, 0, &process);
	return 1;
}
