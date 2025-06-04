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

#include "bpf_tcp_rst.h"

__attribute__((section("kprobe/tcp_reset"), used)) int
tg_event_tcp_reset(struct pt_regs *ctx)
{
	struct sock *skp = (struct sock *)PT_REGS_PARM1(ctx);

	__event_tcp_rst(ctx, skp);
	return 0;
}
