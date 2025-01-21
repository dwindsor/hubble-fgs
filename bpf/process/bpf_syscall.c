// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#include "process_syscall.h"
#include "bpf_tracing.h"

__attribute__((section("tracepoint/sys_enter"), used)) int
sys_enter(struct trace_event_raw_sys_enter *ctx)
{
	record_syscall(ctx->id);
	return 0;
}

char _license[] __attribute__((section("license"), used)) = "GPL";