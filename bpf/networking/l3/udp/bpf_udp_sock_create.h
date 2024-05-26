// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef __BPF_UDP_SOCK_CREATE_H_
#define __BPF_UDP_SOCK_CREATE_H_

#include "vmlinux.h"

#include "api.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "bpf_cookie.h"
#include "bpf_udp_info.h"
#include "bpf_network_helpers.h"
#include "bpf_tracing.h"

static inline __attribute__((always_inline)) int
__tg_udp_init_sock(struct pt_regs *ctx)
{
	u64 pid = get_current_pid_tgid() >> 32;
	struct socketmap_value process = { 0 };
	u64 cookie = (u64)PT_REGS_PARM1(ctx);
	struct execve_map_value *value;
	bool walked;
	u32 ppid;

	if (!cookie) {
		emit_ip_error_event(ctx, 0, 0, false,
				    0, 0, 0, IP_ERROR_SOCK_CREATE_NO_COOKIE);
		return 0;
	}

	if (pid < 1) {
		emit_ip_error_event(ctx, 0, 0, false,
				    0, 0, 0, IP_ERROR_SOCK_CREATE_PID_0);
		return 0;
	}

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
		emit_ip_error_event(ctx, 0, 0, false,
				    0, 0, 0, IP_ERROR_SOCK_CREATE_NO_PROCESS);
		return 1;
	}
	process.create_time = ktime_get_ns();
	process.last_time = process.create_time;

	// Update socket version number.
	process.version = udp_cookie_inc_version();

	// Don't update the tuple map here because the socket hasn't yet
	// been populated.
	add_socketmap(&cookie, &process, false);
	return 0;
}

#endif
