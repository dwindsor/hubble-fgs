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
#define PROCESS_TREE

#include "vmlinux.h"

#include "api.h"
#include "bpf_tcp_security_accept.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

SEC("fentry/security_socket_accept")
int BPF_PROG(tg_security_socket_accept, struct socket *sock, struct socket *newsocket)
{
	return __security_socket_accept(_(sock->sk), newsocket);
}

SEC("fentry/security_sock_graft")
int BPF_PROG(tg_security_sock_graft, struct sock *sk, struct socket *parent)
{
	return __security_sock_graft(ctx, sk, parent);
}
