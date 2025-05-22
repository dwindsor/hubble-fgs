// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef __BPF_POPULATE_TREE_H_
#define __BPF_POPULATE_TREE_H_

#include "vmlinux.h"
#include "bpf_event.h"
#include "../lib/address_family.h"
#include "bpf_tracing.h"
#include "process/process_tree.h"

struct procfs_cfg {
	uint8_t signal_hit;
	uint8_t enabled;
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct procfs_cfg);
	__uint(max_entries, 1);
} tg_procfs_cfg SEC(".maps");

static inline __attribute__((always_inline)) int
__insert_process_tree_procfs(void *ctx, struct task_struct *p, u8 *signal_hit)
{
	int zero = 0, subsys_idx = 0;
	u32 error_flags;
	u64 cgid, cgrpfs_magic = 0;
	struct cgroup *cgrp;
	struct tetragon_conf *tetragon_config;

	tetragon_config = map_lookup_elem(&tg_conf_map, &zero);
	if (tetragon_config) {
		// Select cgroup version
		cgrpfs_magic = tetragon_config->cgrp_fs_magic;
		subsys_idx = tetragon_config->tg_cgrpv1_subsys_idx;
	}

	cgrp = get_task_cgroup(p, cgrpfs_magic, subsys_idx, &error_flags);
	if (!cgrp)
		return 0;

	cgid = get_cgroup_id(cgrp);
	__insert_process_tree(_(p->pid), cgid);

	if (signal_hit)
		*signal_hit = 1;

	return 0;
}

static inline __attribute__((always_inline)) int
populate_app_model(void *ctx, struct task_struct *p)
{
	int zero = 0;
	struct procfs_cfg *config;

	config = map_lookup_elem(&tg_procfs_cfg, &zero);
	if (config && config->enabled)
		__insert_process_tree_procfs(ctx, p, &config->signal_hit);

	return 0;
}

#endif /* __BPF_POPULATE_TREE_H_ */