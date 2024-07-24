// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef __PROCESS_TREE_H__
#define __PROCESS_TREE_H__

#include "vmlinux.h"
#include "api.h"

#include "compiler.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "bpf_process_event.h"
#include "bpf_helpers.h"
#include "bpf_rate.h"
#include "../networking/l3/tcp/bpf_tcp_info.h"

#include "bpf_tracing.h"

#include "networking/bpf_cookie.h"
#include "bpf_tracing.h"

#include "policy_filter.h"
#include "process_endpoint.h"

struct process_tree_config {
	uint64_t enableProcessTree;
	uint64_t bpfGenIds;
};

/* Read only configuration single entry array. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(uint32_t));
	__uint(value_size, sizeof(struct process_tree_config));
} tg_process_tree_config_map SEC(".maps");

int insert_process_tree(void)
{
	struct msg_execve_key *self_uid, *parent_uid;
	__u32 pid = (get_current_pid_tgid() >> 32);
	struct execve_map_value *parent;
	struct process_tree_config *cfg;
	struct process_tree_value *old;
	struct execve_map_value *curr;
	struct process_tree_key *k;
	__u64 cgid, *nsid;
	__u32 zero = 0;

	cfg = map_lookup_elem(&tg_process_tree_config_map, &zero);
	if (!cfg || !cfg->enableProcessTree)
		return 0;

	pid = get_current_pid_tgid();
	curr = execve_map_get_noinit(pid);
	if (!curr)
		return 0;

	k = map_lookup_elem(&process_tree_key_heap, &zero);
	if (!k)
		return 0;

	self_uid = map_lookup_elem(&process_tree_binary_uid_map,
				   &curr->bin);
	if (!self_uid) {
		map_update_elem(&process_tree_uid_binary_map,
				&curr->key, &curr->bin, 0);
		map_update_elem(&process_tree_binary_uid_map,
				&curr->bin, &curr->key, 0);
		self_uid = &curr->key;
	}

	parent = event_find_parent();
	if (!parent)
		goto out;

	parent_uid = map_lookup_elem(&process_tree_binary_uid_map, &parent->bin);
	if (!parent_uid)
		goto out;

	k->parent = *parent_uid;
	k->self = *self_uid;

	cgid = tg_get_current_cgroup_id();
	nsid = map_lookup_elem(&tg_cgroup_namespace_map, &cgid);
	if (nsid)
		k->nsid = *nsid;
	else
		k->nsid = 0;

	old = map_lookup_elem(&process_tree_map, k);
	if (!old) {
		old = map_lookup_elem(&process_tree_value_heap, &zero);
		if (!old)
			return 0;

		old->ktime_last_exec = ktime_get_ns();
		old->ktime_first_exec = ktime_get_ns();
		map_update_elem(&process_tree_map, k, old, 0);
	} else {
		// Duplicating ktime sets in both branches to help verifier and
		// clang generate code that play well together. Otherwise we lose
		// old != NULL on some kernels.
		old->ktime_last_exec = ktime_get_ns();
	}
out:
	return 0;
}

uint64_t glbl_bpf_endpoint_id;

static inline __attribute__((always_inline)) int process_socketmap_add(struct tcpsocketmap_value *v, struct msg_ip_tuple *tuple)
{
	struct msg_execve_key *self_uid, *parent_uid;
	struct destination_endpoint_key destkey;
	struct destination_endpoint_value *dest;
	struct process_tree_config *cfg;
	struct execve_map_value *parent;
	struct execve_map_value *curr;
	__u64 cgid, *nsid;
	int zero = 0;

	struct endpoint_id_key key;
	struct endpoint_id_value *value;

	__u64 source = DESTINATION_SOURCE_USERSPACE;

	if (!v)
		return 0;

	cfg = map_lookup_elem(&tg_process_tree_config_map, &zero);
	if (!cfg || !cfg->enableProcessTree)
		return 0;

	curr = execve_map_get_noinit(v->key.pid);
	if (!curr)
		return 0;

	self_uid = map_lookup_elem(&process_tree_binary_uid_map, &curr->bin);
	if (!self_uid)
		return 0;

	parent = event_find_parent();
	if (!parent)
		return 0;

	parent_uid = map_lookup_elem(&process_tree_binary_uid_map, &parent->bin);
	if (!parent_uid)
		return 0;

	key.addr[0] = tuple->daddr[0];
	key.addr[1] = tuple->daddr[1];

	// destination_id verifier fix to if/else;
	value = map_lookup_elem(&tg_endpoint_id_map, &key);
	if (!value) {
		if (!cfg->bpfGenIds)
			return 0;

		value = map_lookup_elem(&tg_bpf_endpoint_id_map, &key);
		if (!value) {
			value = map_lookup_elem(&tg_bpf_endpoint_id_heap, &zero);
			if (!value)
				return 0;
			value->id = __sync_fetch_and_add(&glbl_bpf_endpoint_id, 1);
			destkey.destination_id = value->id;
			source = DESTINATION_SOURCE_BPF;
			map_update_elem(&tg_bpf_endpoint_id_map, &key, value, 0);
		} else {
			destkey.destination_id = value->id;
		}
	} else {
		destkey.destination_id = value->id;
	}

	destkey.process_id.self = *self_uid;
	destkey.process_id.parent = *parent_uid;
	destkey.source = source;

	cgid = tg_get_current_cgroup_id();
	nsid = map_lookup_elem(&tg_cgroup_namespace_map, &cgid);
	if (nsid)
		destkey.process_id.nsid = *nsid;
	else
		destkey.process_id.nsid = 0;

	dest = map_lookup_elem(&destination_endpoint_map, &destkey);
	if (!dest) {
		struct destination_endpoint_value destvalue;

		destvalue.ktime_create = ktime_get_ns();
		destvalue.addr_create[0] = tuple->daddr[0];
		destvalue.addr_create[1] = tuple->daddr[1];
		map_update_elem(&destination_endpoint_map, &destkey, &destvalue, 0);
	}
	return 0;
}
#endif // __PROCESS_TREE_H__
