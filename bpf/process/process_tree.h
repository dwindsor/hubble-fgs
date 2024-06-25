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
#include "api.h"

#include "compiler.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "bpf_process_event.h"
#include "bpf_helpers.h"
#include "bpf_rate.h"
#include "bpf_tcp_info.h"

#include "bpf_tracing.h"

#include "networking/bpf_cookie.h"
#include "bpf_tracing.h"

#include "policy_filter.h"

#define PROCESS_TREE_SIZE 500000
#define PROCESS_ENDPOINTS 500000

struct endpoint_id_key {
	uint64_t addr[2];
};

struct endpoint_id_value {
	uint64_t id;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, PROCESS_ENDPOINTS);
	__uint(key_size, sizeof(struct endpoint_id_key));
	__uint(value_size, sizeof(struct endpoint_id_value));
} tg_endpoint_id_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, PROCESS_TREE_SIZE);
	__uint(key_size, sizeof(struct binary));
	__uint(value_size, sizeof(struct msg_execve_key));
} process_tree_binary_uid_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, PROCESS_TREE_SIZE);
	__uint(key_size, sizeof(struct msg_execve_key));
	__uint(value_size, sizeof(struct binary));
} process_tree_uid_binary_map SEC(".maps");

struct process_tree_key {
	__u64 nsid;
	struct msg_execve_key self;
};

struct process_tree_value {
	__u64 ktime_first_exec;
	__u64 ktime_last_exec;
	struct process_tree_key parent;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, PROCESS_TREE_SIZE);
	__uint(key_size, sizeof(struct process_tree_key));
	__uint(value_size, sizeof(struct process_tree_value));
} process_tree_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(uint32_t));
	__uint(value_size, sizeof(struct process_tree_key));
} process_tree_key_heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(uint32_t));
	__uint(value_size, sizeof(struct process_tree_value));
} process_tree_value_heap SEC(".maps");

struct destination_endpoint_key {
	struct process_tree_key process_id;
	uint64_t destination_id; // unwrapped endpoint_id_value
};

struct destination_endpoint_value {
	__u64 ktime_create;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, PROCESS_TREE_SIZE);
	__uint(key_size, sizeof(struct destination_endpoint_key));
	__uint(value_size, sizeof(struct destination_endpoint_value));
} destination_endpoint_map SEC(".maps");

int insert_process_tree(void)
{
	struct msg_execve_key *self_uid, *parent_uid;
	__u32 pid = (get_current_pid_tgid() >> 32);
	struct process_tree_value *old;
	struct execve_map_value *curr;
	struct process_tree_key *k;
	__u64 cgid, *nsid;
	__u32 zero = 0;

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
	k->self = *self_uid;

	cgid = tg_get_current_cgroup_id();
	nsid = map_lookup_elem(&tg_cgroup_namespace_map, &cgid);
	if (nsid)
		k->nsid = *nsid;
	else
		k->nsid = 0;

	old = map_lookup_elem(&process_tree_map, k);
	if (!old) {
		struct process_tree_key parent_key = {};
		struct execve_map_value *parent;

		old = map_lookup_elem(&process_tree_value_heap, &zero);
		if (!old)
			return 0;

		old->ktime_last_exec = ktime_get_ns();
		old->ktime_first_exec = ktime_get_ns();

		parent = event_find_parent();
		if (!parent)
			goto out;

		parent_uid = map_lookup_elem(&process_tree_binary_uid_map,
					     &parent->bin);
		if (!parent_uid)
			goto out;

		parent_key.self = *parent_uid;
		parent_key.nsid = k->nsid;
		old->parent = parent_key;
	} else {
		// Duplicating ktime sets in both branches to help verifier and
		// clang generate code that play well together. Otherwise we lose
		// old != NULL on some kernels.
		old->ktime_last_exec = ktime_get_ns();
		old->ktime_first_exec = ktime_get_ns();
	}
out:
	map_update_elem(&process_tree_map, k, old, 0);
	return 0;
}

static inline __attribute__((always_inline)) int process_socketmap_add(struct tcpsocketmap_value *v)
{
	struct destination_endpoint_key destkey;
	struct destination_endpoint_value *dest;
	struct msg_execve_key *self_uid;
	struct execve_map_value *curr;
	__u64 cgid, *nsid;

	struct endpoint_id_key key;
	struct endpoint_id_value *value;

	if (!v)
		return 0;

	key.addr[0] = v->tuple.daddr[0];
	key.addr[1] = v->tuple.daddr[1];

	value = map_lookup_elem(&tg_endpoint_id_map, &key);
	if (!value)
		return 0;

	curr = execve_map_get_noinit(v->key.pid);
	if (!curr)
		return 0;

	self_uid = map_lookup_elem(&process_tree_binary_uid_map,
				   &curr->bin);
	if (!self_uid)
		return 0;
	destkey.process_id.self = *self_uid;

	cgid = tg_get_current_cgroup_id();
	nsid = map_lookup_elem(&tg_cgroup_namespace_map, &cgid);
	if (nsid)
		destkey.process_id.nsid = *nsid;
	else
		destkey.process_id.nsid = 0;

	destkey.destination_id = value->id;
	dest = map_lookup_elem(&destination_endpoint_map, &destkey);
	if (!dest) {
		struct destination_endpoint_value v;

		v.ktime_create = ktime_get_ns();
		map_update_elem(&destination_endpoint_map, &destkey, &v, 0);
	}
	return 0;
}
