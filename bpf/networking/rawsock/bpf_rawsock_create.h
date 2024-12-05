// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef BPF_RAWSOCK_CREATE_H
#define BPF_RAWSOCK_CREATE_H

#include "vmlinux.h"

#include "api.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "../bpf_cookie.h"
#include "../bpf_network_helpers.h"
#include "bpf_tracing.h"
#include "../socktrack/bpf_sk_alloc.h"

static inline __attribute__((always_inline)) int
__rawsock_sk_init(void *ctx, u64 cookie)
{
	struct sock *sk;
	u16 skc_num;

	sk = (struct sock *)cookie;
	probe_read_kernel(&skc_num, sizeof(skc_num), _(&(sk->__sk_common.skc_num)));
	if (skc_num == IPPROTO_ICMP || skc_num == IPPROTO_ICMP6)
		return store_socket(ctx, cookie, IPPROTO_ICMP);
	return store_socket(ctx, cookie, IPPROTO_RAW);
}

#endif
