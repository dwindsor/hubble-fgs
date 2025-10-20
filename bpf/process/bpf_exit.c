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
#include "../../modules/tetragon-oss/bpf/process/bpf_exit.h"
#include "../../modules/tetragon-oss/bpf/include/bpf_ktime.h"
#include "../networking/l3/tcp/bpf_tcp_info.h"
#include "../networking/bpf_process_network_watermarks.h"
#include "process_endpoint.h"
#include "bpf_tracing.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

/*
 * Update process tree with exit timestamp
 */
FUNC_INLINE void update_process_tree_exit_time(__u32 tgid)
{
	struct process_tree_key *tree_key;
	struct process_tree_value *tree_val;

	/* Look up the process tree key for this PID */
	tree_key = map_lookup_elem(&tg_ee_pid_data, &tgid);
	if (!tree_key)
		return;

	/* Update the process tree value with exit timestamp */
	tree_val = map_lookup_elem(&process_tree_map, tree_key);
	if (tree_val)
		tree_val->ktime_latest_exit = tg_get_ktime();
}

/*
 * Hooking on acct_process kernel function, which is called on the task's
 * exit path once the task is the last one in the group. It's stable since
 * v4.19, so it's safe to hook for us.
 *
 * It's initialized for thread leader:
 *
 *   clone {
 *     copy_process
 *       copy_signal
 *         atomic_set(&sig->live, 1);
 *   }
 *
 * Incremented for each new thread:
 *
 *   clone {
 *     copy_process
 *       atomic_inc(&current->signal->live);
 *     ...
 *     wake_up_new_task
 *   }
 *
 * Decremented for each exiting thread:
 *
 *   do_exit {
 *     group_dead = atomic_dec_and_test(&tsk->signal->live);
 *     ...
 *     if (group_dead)
 *              acct_process();
 *     ...
 *   }
 *
 * Hooking to acct_process we ensure tsk->signal->live is 0 and
 * we are the last one of the thread group.
 */
__attribute__((section("kprobe/acct_process"), used)) int
event_exit_acct_process(struct pt_regs *ctx)
{
	__u32 tgid = get_current_pid_tgid() >> 32;

	/* Update process tree exit timestamp */
	update_process_tree_exit_time(tgid);

	process_watermarks_map_delete(ctx, tgid);
	event_exit_send((void *)ctx, tgid);

	return 0;
}

/*
 * Hooking on acct_process kernel function, which is called on the task's
 * exit path once the task is the last one in the group. It's stable since
 * v4.19, so it's safe to hook for us.
 *
 * It's called with on_exit argument != 0 when called from do_exit
 * function with same conditions like for acct_process described above.
 */
__attribute__((section("kprobe/disassociate_ctty"), used)) int
event_exit_disassociate_ctty(struct pt_regs *ctx)
{
	int on_exit = (int)PT_REGS_PARM1_CORE(ctx);

	if (on_exit) {
		__u32 tgid = get_current_pid_tgid() >> 32;

		/* Update process tree exit timestamp */
		update_process_tree_exit_time(tgid);

		process_watermarks_map_delete(ctx, tgid);
		event_exit_send(ctx, tgid);
	}

	return 0;
}
