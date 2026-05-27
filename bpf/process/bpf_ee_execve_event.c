// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"

#include "compiler.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "bpf_process_event.h"
#include "bpf_helpers.h"
#include "bpf_rate.h"
#include "lib/common.h"

#define MAX_SELECTORS 5
#include "policy_filter.h"
#include "process_tree.h"

#ifdef __RHEL7_BPF_PROG
#define ee_exec_ctx_struct ftrace_raw_sched_process_exec
#else
#define ee_exec_ctx_struct trace_event_raw_sched_process_exec
#endif

#ifdef __V612_BPF_PROG

int execve_rate(void *ctx);
int ee_execve_send(struct ee_exec_ctx_struct *ctx __arg_ctx);

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__array(values, int(void *));
} execve_calls SEC(".maps") = {
	.values = {
		[0] = (void *)&execve_rate,
		[1] = (void *)&ee_execve_send,
	},
};

#define OVERRIDE_TAILCALL
#include "bpf_execve_event.c"

__attribute__((section("tracepoint"), used)) int
ee_execve_send(struct ee_exec_ctx_struct *ctx)
{
	execve_send(ctx);
	insert_process_tree();
	return 0;
}

#else

int execve_rate(void *ctx);
int oss_execve_send(struct ee_exec_ctx_struct *ctx __arg_ctx);
int execve_send(struct ee_exec_ctx_struct *ctx __arg_ctx);

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__array(values, int(void *));
} execve_calls SEC(".maps") = {
	.values = {
		[0] = (void *)&execve_rate,
		[1] = (void *)&execve_send,
	},
};

#define execve_send                                           \
	execve_send(struct ee_exec_ctx_struct *ctx __arg_ctx) \
	{                                                     \
		oss_execve_send(ctx);                         \
		insert_process_tree();                        \
		return 0;                                     \
	}                                                     \
	__attribute__((always_inline)) int oss_execve_send

#define OVERRIDE_TAILCALL
#include "bpf_execve_event.c"

#endif /* __V612_BPF_PROG */
