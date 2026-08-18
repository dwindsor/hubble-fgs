// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef __PROCESS_TREE_EXEC_IDS_H__
#define __PROCESS_TREE_EXEC_IDS_H__

#include "vmlinux.h"
#include "compiler.h"
#include "bpf_helpers.h"
#include "lib/process.h"

#define PROCESS_TREE_EXEC_IDS_MAX 8

struct process_tree_exec_ids {
	struct msg_execve_key exec_ids[PROCESS_TREE_EXEC_IDS_MAX];
	__u64 cur_head;
	__u64 cur_len;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1); // will be resized by userspace
	__type(key, struct tree_id);
	__type(value, struct process_tree_exec_ids);
} tg_pstree_eids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct process_tree_exec_ids);
} tg_execid_tmp SEC(".maps");

/* Arguments are passed by pointer because this is inlined into the
 * __insert_process_tree call chain, which is close to the 512 byte BPF stack limit.
 */
static inline __attribute__((always_inline)) void record_exec_id(struct tree_id *key,
								 struct msg_execve_key *exec_id)
{
	__u32 zero = 0;
	struct process_tree_exec_ids *ids;

	ids = map_lookup_elem(&tg_pstree_eids, key);
	if (!ids) {
		ids = map_lookup_elem(&tg_execid_tmp, &zero);
		if (!ids)
			return;
		ids->exec_ids[0] = *exec_id;
		ids->cur_head = 1;
		ids->cur_len = 1;
		map_update_elem(&tg_pstree_eids, key, ids, BPF_ANY);
		return;
	}

	if (ids->cur_head >= PROCESS_TREE_EXEC_IDS_MAX)
		return;

	ids->exec_ids[ids->cur_head] = *exec_id;
	ids->cur_head = (ids->cur_head + 1) % PROCESS_TREE_EXEC_IDS_MAX;
	if (ids->cur_len < PROCESS_TREE_EXEC_IDS_MAX)
		ids->cur_len++;
}

#endif // __PROCESS_TREE_EXEC_IDS_H__
