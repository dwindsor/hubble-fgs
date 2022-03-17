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
#include "cookie.h"

char _license[] __attribute__((section(("license")), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

__attribute__((section(("kprobe/inet_release")), used)) int
sock_release(struct pt_regs *ctx)
{
	struct socket *socket = (void *)((ctx)->di);
	struct sock *sk;
	__u64 cookie;

	probe_read(&sk, sizeof(sk), _(&(socket->sk)));
	cookie = get_cookie(sk);
	if (!cookie)
		return 0;
	map_delete_elem(&socket_cookie_to_proc_map, &cookie);
	return 0;
}
