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

#define SK_MSG

#include "egress.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

__attribute__((section("sk_msg/fgs_tls"), used)) int
bpf_tls_sk_msg_fgs(struct sk_msg_md *skmsg)
{
	u64 cookie = (u64)skmsg->sk;
	bpf_parse_tls_egress(skmsg, &cookie);
	return SK_PASS;
}
