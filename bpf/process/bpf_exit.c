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
#include "../networking/l3/tcp/bpf_tcp_info.h"
#include "../networking/bpf_process_network_watermarks.h"
#include "process_endpoint.h"
#include "process_tree.h"
#include "bpf_tracing.h"
#include "compiler.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "bpf_rate.h"
#include "process.h"
#include "bpf_process_event.h"
#include "bpf_ktime.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

FUNC_INLINE void
event_exit_fill(struct msg_exit *exit, __u32 tgid, __u64 enter_ktime,
		struct task_struct *task)
{
	exit->common.op = MSG_OP_EXIT;
	exit->common.flags = 0;
	exit->common.pad[0] = 0;
	exit->common.pad[1] = 0;
	exit->common.size = sizeof(*exit);
	exit->common.ktime = tg_get_ktime();

	exit->current.pid = tgid;
	exit->current.pad[0] = 0;
	exit->current.pad[1] = 0;
	exit->current.pad[2] = 0;
	exit->current.pad[3] = 0;
	exit->current.ktime = enter_ktime;

	/**
	 * Per thread tracking rules TID == PID :
	 *  We want the exit event to match the exec one, and since during exec
	 *  we report the thread group leader, do same here as we read the exec
	 *  entry from the execve_map anyway and explicitly set it to the to tgid.
	 */
	exit->info.tid = tgid;
	with_errmetrics(probe_read, &exit->info.code, sizeof(exit->info.code),
			_(&task->exit_code));
}

#ifdef __V511_BPF_PROG
FUNC_INLINE int
rb_exit_output(void *ctx, struct execve_map_value *enter, __u32 tgid)
{
	struct task_struct *task = (struct task_struct *)get_current_task();
	struct msg_exit *exit;

	exit = event_ringbuf_reserve(MSG_OP_EXIT, sizeof(struct msg_exit));
	if (!exit)
		return 0;
	event_exit_fill(exit, tgid, enter->key.ktime, task);
	ringbuf_submit(exit, 0);
	return 0;
}
#endif

FUNC_INLINE void
perf_exit__output(void *ctx, struct execve_map_value *enter, __u32 tgid)
{
	struct task_struct *task = (struct task_struct *)get_current_task();
	struct msg_exit exit;

	event_exit_fill(&exit, tgid, enter->key.ktime, task);
	event_output_metric(ctx, MSG_OP_EXIT, &exit, sizeof(struct msg_exit));
}

FUNC_INLINE void event_exit_send(void *ctx, __u32 tgid)
{
	struct execve_map_value *enter;

	/* It is safe to do a map_lookup_event() here because
	 * we must have captured the execve case in order for an
	 * exit to happen. Or in the FGS startup case we pre
	 * populated it before loading BPF programs. At any rate
	 * if the entry is _not_ in the execve_map the lookup
	 * will create an empty entry, the ktime check below will
	 * catch it and we will quickly delete the entry again.
	 */
	enter = execve_map_get_noinit(tgid);
	if (!enter)
		return;
	if (enter->key.ktime) {
#ifdef __V511_BPF_PROG
		if (!CONFIG(USE_PERF_RING_BUF))
			rb_exit_output(ctx, enter, tgid);
		else
#endif
			perf_exit__output(ctx, enter, tgid);
	}

	execve_map_delete(tgid);
	map_delete_elem(&tg_parents_bin, &enter->key.pid);
}

/*
 * Update process tree with exit timestamp and update count
 */
FUNC_INLINE void update_process_tree_exit(__u32 tgid)
{
	struct process_tree_key *tree_key;
	struct process_tree_key tree_key_copy;
	struct process_tree_value *tree_val;

	/* Look up the process tree key for this PID */
	tree_key = map_lookup_elem(&tg_ee_pid_data, &tgid);
	if (!tree_key)
		return;

	/* Update the process tree value with exit timestamp */
	tree_val = map_lookup_elem(&process_tree_map, tree_key);
	if (!tree_val) {
		// There really shouldn't be a process tree key but no mapping from the
		// key to a value. This could occur if the process was new (wlid was 0)
		// and the app model server updated the wlid and cgid with workload
		// info. We might need to update the value in tg_ee_pid_data (which has
		// a separate process tree key) with the new workload.

		__u64 cgid = tg_get_current_cgroup_id();
		__u64 *my_wlid = map_lookup_elem(&tg_cgid_wlid, &cgid);

		if (!my_wlid || *my_wlid == 0)
			return;

		tree_key_copy = *tree_key;
		tree_key_copy.wlid = *my_wlid;
		tree_key_copy.cgid = cgid;
		map_update_elem(&tg_ee_pid_data, &tgid, &tree_key_copy, 0);

		tree_val = map_lookup_elem(&process_tree_map, &tree_key_copy);
		if (!tree_val)
			return;
	}

	tree_val->ktime_latest_exit = tg_get_ktime();
	tree_val->exit_count++;
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

	/* Update process tree exit timestamp/count */
	update_process_tree_exit(tgid);

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

		/* Update process tree exit timestamp/count */
		update_process_tree_exit(tgid);

		process_watermarks_map_delete(ctx, tgid);
		event_exit_send(ctx, tgid);
	}

	return 0;
}
