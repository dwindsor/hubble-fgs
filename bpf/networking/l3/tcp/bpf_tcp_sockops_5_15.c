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

#define KERNEL_5_15
#include "bpf_tcp_connect.h"

__attribute__((section("sockops/tcp_sockops"), used)) int
tg_event_tcp_sockops(struct bpf_sock_ops *skops)
{
	__u32 family = skops->family;

	if (family != AF_INET && family != AF_INET6)
		return 0;

	switch (skops->op) {
	case BPF_SOCK_OPS_TCP_CONNECT_CB:
		__event_tcp_connect_sockops(skops);
		break;
	default:
		break;
	}
	return 0;
}
