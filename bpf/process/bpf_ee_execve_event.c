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

#include "policy_filter.h"

int oss_execve_send(void *ctx);

#define execve_send                   \
	execve_send(void *ctx)        \
	{                             \
		oss_execve_send(ctx); \
		return 0;             \
	}                             \
	__attribute__((always_inline)) int oss_execve_send

#include "bpf_execve_event.c"
