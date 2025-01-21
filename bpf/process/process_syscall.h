// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef __PROCESS_SYSCALL_H__
#define __PROCESS_SYSCALL_H__

#include "vmlinux.h"
#include "lib/common.h"
#include "lib/process.h"
#include "process_endpoint.h"

#define SYSCALL_BITMASK_SIZE 16

struct process_syscall_value {
	__u64 syscalls[SYSCALL_BITMASK_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1); // will be resized by user space
	__type(key, struct tree_id);
	__type(value, struct process_syscall_value);
} tg_syscall_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct process_syscall_value);
} tg_syscall_heap SEC(".maps");

static inline __attribute__((always_inline)) int record_syscall(__u64 id)
{
	struct process_tree_key *process_key;
	struct process_syscall_value *old;
	int idx;
	__u32 zero = 0;
	__u32 pid = get_current_pid_tgid();

	if (unlikely(id < 0)) {
		DEBUG("syscall: id < 0, id=%ld", id);
		return 0;
	}

	process_key = map_lookup_elem(&tg_ee_pid_data, &pid);
	if (!process_key) {
		return 0;
	}

	old = map_lookup_elem(&tg_syscall_map, &process_key->self);
	if (!old) {
		old = map_lookup_elem(&tg_syscall_heap, &zero);
		if (!old)
			return 0;
		// Same as id / 64
		idx = id >> 6;
		asm volatile("%[idx] &= 15;\n"
			     : [idx] "+r"(idx)::);
		old->syscalls[idx] |= (1llu << (id % 64));
		map_update_elem(&tg_syscall_map, &process_key->self, old, 0);
	} else {
		// Same as id / 64
		idx = id >> 6;
		asm volatile("%[idx] &= 15;\n"
			     : [idx] "+r"(idx)::);
		old->syscalls[idx] |= (1llu << (id % 64));
	}

	return 0;
}

#endif