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

#include "api.h"
#include "hubble_msg.h"
#include "bpf_events.h"
#include "bpf_udp.h"
#include "cookie.h"

char _license[] __attribute__((section(("license")), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

#define AF_INET	 2
#define AF_INET6 10

__attribute__((section(("kretprobe/sk_alloc")), used)) int
sk_allocret(struct pt_regs *ctx)
{
	u64 pid = get_current_pid_tgid();
	u64 cookie = ctx->ax;
	struct sock *sk = (void *)cookie;
	struct execve_map_value *value;
	u16 family;

	if (cookie == 0 || (pid >> 32) <= 1) {
		return 0;
	}

	probe_read(&family, sizeof(u16), &sk->__sk_common.skc_family);
	if (family != AF_INET && family != AF_INET6)
		return 0;

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
		map_update_elem(&socket_cookie_to_proc_map, &cookie, &v, 0);
	} else {
		map_update_elem(&socket_cookie_to_proc_map, &cookie, value, 0);
	}

	return 0;
}
