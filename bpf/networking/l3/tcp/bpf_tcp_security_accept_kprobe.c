// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.
//

#include "vmlinux.h"

#include "api.h"
#include "bpf_tcp_security_accept.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

__attribute__((section("kprobe/security_socket_accept"), used)) int
tg_security_socket_accept(struct pt_regs *ctx)
{
	struct socket *newsocket = (struct socket *)PT_REGS_PARM2(ctx);
	struct socket *sock = (struct socket *)PT_REGS_PARM1(ctx);
	struct sock *sk;

	probe_read_kernel(&sk, sizeof(sk), _(&(sock->sk)));

	return __security_socket_accept(sk, newsocket);
}

__attribute__((section("kprobe/security_sock_graft"), used)) int
tg_security_sock_graft(struct pt_regs *ctx)
{
	struct socket *parent = (struct socket *)PT_REGS_PARM2(ctx);
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

	return __security_sock_graft(ctx, sk, parent);
}
