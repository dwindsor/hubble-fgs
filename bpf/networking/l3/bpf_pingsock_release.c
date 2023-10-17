#include "vmlinux.h"

#include "api.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "../cookie.h"
#include "bpf_tracing.h"

#define IPPROTO_ICMPFORIPV6 58

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct msg_ip_event);
	__uint(max_entries, 1);
} udp_close_event_map SEC(".maps");

// Some environments init ping sockets, send ping over ping sockets,
// and then close ping sockets. Other environments, however, init ping
// sockets, init a raw socket, sends ping over the raw socket, and then
// closes the raw socket, but doesn't close the ping sockets.
// As such, we choose to solely use __sk_free to catch the sockets being
// discarded. The original raw_close and ping_close programs are retained
// (in comments) in case we decide to revert.

/*
// raw sockets are used in some environments
__attribute__((section("kprobe/raw_close"), used)) int
tg_raw_close(struct pt_regs *ctx)
{
	__u64 cookie = PT_REGS_PARM1(ctx);

	del_socketmap(&cookie);
	return 1;
}

// ping sockets are used in other environments
__attribute__((section("kprobe/ping_close"), used)) int
tg_ping_close(struct pt_regs *ctx)
{
	__u64 cookie = PT_REGS_PARM1(ctx);

	del_socketmap(&cookie);
	return 1;
}
*/

// In some environments, ping sockets are initialised and not closed, so we use
// __sk_free to catch those and remove them from the socket map.
__attribute__((section("kprobe/__sk_free"), used)) int
tg_sk_free(struct pt_regs *ctx)
{
	__u64 cookie = PT_REGS_PARM1(ctx);
	struct sock *sk = (struct sock *)cookie;
	u16 protocol;

	probe_read(&protocol, sizeof(protocol), _(&(sk->sk_protocol)));
	if (bpf_core_field_size(sk->sk_protocol) == sizeof(u32))
		protocol >>= 8;

	if (protocol != IPPROTO_ICMP && protocol != IPPROTO_ICMPFORIPV6)
		return 1;
	del_socketmap(&cookie);
	return 1;
}
