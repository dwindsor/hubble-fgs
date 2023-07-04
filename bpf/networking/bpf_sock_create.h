#include "vmlinux.h"

#include "api.h"
#include "hubble_msg.h"
#include "bpf_events.h"
#include "bpf_udp.h"
#include "cookie.h"
#include "bpf_fd_lookup.h"
#include "../lib/address_family.h"
#include "bpf_tracing.h"

static inline __attribute__((always_inline)) int
__sk_allocret(struct pt_regs *ctx)
{
	u64 pid = get_current_pid_tgid() >> 32;
	u64 cookie = PT_REGS_RC(ctx);
	struct sock *sk = (struct sock *)cookie;
	struct execve_map_value *value;
	u16 family;
	struct socketmap_value process = { 0 };
	u32 ppid;
	bool walked;
	long family_ret;

	if (!cookie) {
		emit_ip_error_event(ctx, 0, 0, false,
				    0, 0, 0, IP_ERROR_SOCK_CREATE_NO_COOKIE);
		return 0;
	}

	if (pid < 1) {
		emit_ip_error_event(ctx, 0, 0, false,
				    0, 0, 0, IP_ERROR_SOCK_CREATE_PID_0);
		return 0;
	}

	family_ret = probe_read(&family, sizeof(u16), _(&(sk->__sk_common.skc_family)));
	if (family_ret == 0 && family != AF_INET && family != AF_INET6)
		return 0;

	/* There is no guarantee that the protocol has been set so we cannot
	 * check it. We will store all socket allocations for all IPv4 and IPv6
	 * protocols.
	 */

	/* Ideally we would be able to bind the socket to create early,
	 * but its possible that we don't have an entry for the thread
	 * if its a child thread, etc. Perhaps we should always have
	 * entries, but we don't at the moment. So to ensure we don't
	 * mislead the next layer to process this we not only need to
	 * check if the entry exists but also that ktime!=0 which would
	 * indicate its a stale entry that we are preparing to GC.
	 */
	value = event_find_curr(&ppid, &walked);
	if (value && value->key.ktime) {
		process.key.pid = value->key.pid;
		process.key.ktime = value->key.ktime;
	} else {
		emit_ip_error_event(ctx, 0, 0, false,
				    0, 0, 0, IP_ERROR_SOCK_CREATE_NO_PROCESS);
		return 1;
	}
	process.create_time = ktime_get_ns();
	add_socketmap(&cookie, 0, &process);
	return 1;
}
