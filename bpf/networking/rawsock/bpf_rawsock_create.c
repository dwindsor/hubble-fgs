// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#include "vmlinux.h"

#include "api.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "../bpf_cookie.h"
#include "../bpf_network_helpers.h"
#include "bpf_tracing.h"
#include "bpf_rawsock.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

static inline __attribute__((always_inline)) int
store_socket(void *ctx, u64 cookie, u8 protocol);

__attribute__((section("kprobe/raw_sk_init"), used)) int
tg_rawsock_sk_init(struct pt_regs *ctx)
{
	u64 cookie = (u64)PT_REGS_PARM1(ctx);
	struct sock *sk;
	u16 skc_num;

	sk = (struct sock *)cookie;
	probe_read_kernel(&skc_num, sizeof(skc_num), _(&(sk->__sk_common.skc_num)));
	if (skc_num != IPPROTO_ICMP)
		return store_socket(ctx, cookie, IPPROTO_RAW);
	return 0;
}

// IPv6 version
__attribute__((section("kprobe/rawv6_init_sk"), used)) int
tg_rawsockv6_init_sk(struct pt_regs *ctx)
{
	u64 cookie = (u64)PT_REGS_PARM1(ctx);
	struct sock *sk;
	u16 skc_num;

	sk = (struct sock *)cookie;
	probe_read_kernel(&skc_num, sizeof(skc_num), _(&(sk->__sk_common.skc_num)));
	if (skc_num != IPPROTO_ICMP6)
		return store_socket(ctx, cookie, IPPROTO_RAW);
	return 0;
}

__attribute__((section("kprobe/__register_prot_hook"), used)) int
tg_raw_packet_reg_prot_hook(struct pt_regs *ctx)
{
	u64 cookie = (u64)PT_REGS_PARM1(ctx);

	return store_socket(ctx, cookie, IPPROTO_RAW);
}

static inline __attribute__((always_inline)) int
store_socket(void *ctx, u64 cookie, u8 protocol)
{
	u64 pid = get_current_pid_tgid() >> 32;
	struct socketmap_value process = { 0 };
	struct execve_map_value *value;
	bool walked;
	u32 ppid;

	if (!cookie) {
		emit_ip_error_event(ctx, 0, 0, false,
				    0, 0, 0, IP_ERROR_SOCK_CREATE_NO_COOKIE);
		return 0;
	}

	if (pid < 1) {
		emit_ip_error_event(ctx, 0, &cookie, false,
				    0, 0, 0, IP_ERROR_SOCK_CREATE_PID_0);
		return 0;
	}

	struct sock *sk = (struct sock *)cookie;
	u16 skc_num;
	probe_read_kernel(&skc_num, sizeof(skc_num), _(&(sk->__sk_common.skc_num)));

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
		emit_ip_error_event(ctx, 0, &cookie, false,
				    0, 0, 0, IP_ERROR_SOCK_CREATE_NO_PROCESS);
		return 1;
	}
	process.create_time = ktime_get_ns();
	process.protocol = protocol;
	// Don't update the tuple map because this is a ping/raw socket.
	add_socketmap(&cookie, &process, false);
	emit_rawsock_event(ctx, &process, cookie, ISO_MSG_OP_RAWSOCK_CREATE);
	return 0;
}
