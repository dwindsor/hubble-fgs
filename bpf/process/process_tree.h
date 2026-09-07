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
#include "bpf_ktime.h"
#include "networking/l3/tcp/bpf_tcp_info.h"
#include "networking/l3/icmp/bpf_icmp.h"

#include "bpf_tracing.h"

#include "networking/bpf_cookie.h"
#include "bpf_tracing.h"

#define MAX_SELECTORS 5
#include "policy_filter.h"
#include "process_endpoint.h"
#include "process_tree_exec_ids.h"
#include "lpm.h"

#include "parsers/dns/dns_pstree.h"

struct process_tree_config {
	uint64_t enableProcessTree;
	uint64_t bpfGenIds;
	uint64_t track_exec_ids;
	/* Bumped by userspace on every datapath record add or remove. A socket on an
	 * older generation re-resolves, so a policy applied mid-connection takes
	 * effect.
	 */
	uint32_t policy_generation;
	uint32_t pad;
};

/* Read only configuration single entry array. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, uint32_t);
	__type(value, struct process_tree_config);
} tg_process_tree_config_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(uint32_t));
	__uint(value_size, sizeof(uint64_t));
} tg_tree_id SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1); // will be resized by userspace
	__type(key, u64); // cgroup ID
	__type(value, u64); // state ID
} tg_cgid_wlid SEC(".maps");

static void get_tree_id(struct tree_id *id)
{
	u32 zero = 0;
	u64 *counter;

	counter = map_lookup_elem(&tg_tree_id, &zero);
	if (!counter) {
		id->uid = 0;
		tree_id_set_ignore_args(id, false);
		return;
	}

	id->uid = ++(*counter);
	id->cpu = get_smp_processor_id();
	/* ignore_args cleared via tree_id_set_ignore_args earlier */
	DEBUG_PROCESS("ID: %d.%d\n", id->cpu, id->uid);
	return;
}

char global_zero[MAXARGLENGTH] = { 0 };

/* find_my_self, will lookup the UID for this process or create one if it is
 * not found. Unfortunately, not all verifiers can track the PID from the
 * callers easily resulting in verifier errors so we mark it inline which
 * fixes the issue because that removes the function call.
 */
static inline __attribute__((always_inline)) uint64_t __find_my_self(struct execve_map_value *curr, __u32 pid)
{
	struct process_tree_binary_uid_key *tree_key;
	struct tree_id *self_uid, new_uid;
	int zero = 0;

	tree_key = map_lookup_elem(&tg_h_ps_buidkey, &zero);
	if (!tree_key) {
		return 0;
	}

	// Process UID is done in the following order. First check if there
	// is a binary key with empty args. This is needed for policy that
	// does not specify args. Next lookup the fully qualified process
	// with args key. And finally generate an ID.
	probe_read_kernel(&tree_key->binary, BINARY_PATH_MAX_LEN, curr->bin.path);
	probe_read_kernel(&tree_key->args, MAXARGLENGTH, global_zero);
	self_uid = map_lookup_elem(&process_tree_binary_uid_map, tree_key);
	// In cases where a process already exists with no arguments, it might look
	// like a uid that has been created by a policy that does not specify args.
	// If ignore_args == 0, we know that this is such a case and proceed as
	// if we hadn't found a match. If this process also doesn't have args, it
	// will match in the next step regardless.
	if (!self_uid || !tree_id_get_ignore_args(self_uid)) {
		DEBUG_PROCESS("%s: second lookup with args, ignore_args=%d",
			      __func__, self_uid ? tree_id_get_ignore_args(self_uid) : -1);
		probe_read_kernel(&tree_key->args, curr->args.len & (MAXARGLENGTH - 1), curr->args.buf);
		self_uid = map_lookup_elem(&process_tree_binary_uid_map, tree_key);
	}

	if (self_uid) {
		uint64_t result = ((uint64_t)self_uid->cpu << 32) | (uint64_t)self_uid->uid;
		return result;
	}

	get_tree_id(&new_uid);
	if (!new_uid.uid)
		return 0;
	map_update_elem(&process_tree_binary_uid_map, tree_key, &new_uid, 0);
	uint64_t result = ((uint64_t)new_uid.cpu << 32) | (uint64_t)new_uid.uid;

	DEBUG_PROCESS("%s: generated new tree_id=%llu", __func__, result);
	return result;
}

/* tree_id is a u64 don't worry about returning it directly */
static inline __attribute__((always_inline)) uint64_t find_my_self(__u32 pid)
{
	struct execve_map_value *curr;

	/* PID=0 is kernel threads we don't need to police the kernel. And
	 * this is acctually here to bound pid for verifier.
	 */
	if (!pid)
		return 0;

	curr = execve_map_get_noinit(pid);
	if (!curr)
		return 0;
	return __find_my_self(curr, pid);
}

int find_my_wlid(__u64 cgid)
{
	__u64 *wlid;

	wlid = map_lookup_elem(&tg_cgid_wlid, &cgid);
	if (wlid)
		return *wlid;
	return 0;
}

int __insert_process_tree(__u32 pid, __u64 cgid)
{
	struct process_tree_key *k, local = { 0 }, *parent;
	struct process_tree_binary_uid_key *buid_scratch;
	struct process_tree_config *cfg;
	struct process_tree_value *old;
	struct execve_map_value *curr;
	__u64 zero = 0, uid = 0;

	cfg = map_lookup_elem(&tg_process_tree_config_map, &zero);
	if (!cfg || !cfg->enableProcessTree)
		return 0;

	curr = execve_map_get_noinit(pid);
	if (!curr)
		return 0;

	parent = map_lookup_elem(&tg_ee_pid_data, &curr->pkey.pid);
	k = &local;
	if (parent) {
		memcpy(k->path, parent->path, sizeof(u64) * 8);
		__u32 index = (parent->depth) & 0xff;
		if (index >= 8)
			index = 7;
		k->path[index] = parent->self;
		k->depth = index + 1;
	} else {
		k->depth = 0;
		tree_id_clear(&k->path[0]);
		tree_id_clear(&k->path[1]);
		tree_id_clear(&k->path[2]);
		tree_id_clear(&k->path[3]);
		tree_id_clear(&k->path[4]);
		tree_id_clear(&k->path[5]);
		tree_id_clear(&k->path[6]);
		tree_id_clear(&k->path[7]);
	}

	/* Obtain (and potentially allocate) a tree id for this process. */
	uid = find_my_self(pid);
	if (!uid)
		return 0;
	k->self.uid = uid & 0xffffffff;
	k->self.cpu = uid >> 32; /* retains ignore_args bit in high bit */
	if (cfg->track_exec_ids)
		record_exec_id(&k->self, &curr->key);
	k->wlid = find_my_wlid(cgid);
	// If the workload id is non-zero, fill in the cgid so the app model server
	// can separate containers for the same workload.
	if (k->wlid != 0)
		k->cgid = cgid;

	/* Retrieve the per-CPU scratch populated by find_my_self with
	 * binary path and args for this process.
	 */
	buid_scratch = map_lookup_elem(&tg_h_ps_buidkey, &zero);

	map_update_elem(&tg_ee_pid_data, &pid, &local, 0);
	DEBUG_PROCESS("curr->nspid=%d curr->key.pid=%d", curr->nspid, curr->key.pid);

	old = map_lookup_elem(&process_tree_map, k);
	if (!old) {
		old = map_lookup_elem(&tg_h_ps_value, &zero);
		if (!old)
			return 0;

		old->in_init_tree = curr->flags & EVENT_IN_INIT_TREE;
		old->in_container = curr->nspid != 0;
		old->ktime_last_exec = tg_get_ktime();
		old->ktime_first_exec = old->ktime_last_exec;
		old->cgid = cgid;
		old->exec_count = 1;
		old->exit_count = 0;
		old->maybe_missing_nsid = 0;
		if (k->wlid == 0 && old->in_container) {
			// inform userspace that we might need to update the wlid mapping for this process when it becomes available
			DEBUG_PROCESS("missing wlid pid=%d cgid=%d", pid, cgid);
			old->maybe_missing_nsid = 1;
		}
		if (buid_scratch) {
			__bpf_memcpy_builtin(old->binary, buid_scratch->binary, BINARY_PATH_MAX_LEN);
			__bpf_memcpy_builtin(old->args, buid_scratch->args, MAXARGLENGTH);
		}
		map_update_elem(&process_tree_map, k, old, 0);
	} else {
		// Duplicating ktime sets in both branches to help verifier and
		// clang generate code that play well together. Otherwise we lose
		// old != NULL on some kernels.
		old->in_init_tree = curr->flags & EVENT_IN_INIT_TREE;
		old->in_container = curr->nspid != 0;
		old->ktime_last_exec = tg_get_ktime();
		old->cgid = cgid;
		__sync_fetch_and_add(&old->exec_count, 1);
		if (k->wlid == 0 && old->in_container) {
			// inform userspace that we might need to update the wlid mapping for this process when it becomes available
			DEBUG_PROCESS("missing wlid pid=%d cgid=%d", pid, cgid);
			old->maybe_missing_nsid = 1;
		}
	}
	return 0;
}

int insert_process_tree(void)
{
	int err = 0;
#if defined(__V511_BPF_PROG) || defined(__V60_BPF_PROG) || defined(__V61_BPF_PROG) || defined(__V63_BPF_PROG) || defined(__V612_BPF_PROG)
	__u32 pid = get_current_pid_tgid();
	__u64 cgid = tg_get_current_cgroup_id();

	err = __insert_process_tree(pid, cgid);
#endif
	return err;
}

uint64_t glbl_bpf_endpoint_id = 1;

__u64 tg_sockops_get_current_cgroup_id(void)
{
	int zero = 0, subsys_idx = 0;
	struct tetragon_conf *conf;
	struct task_struct *task;
	struct cgroup *cgrp;
	__u64 cgrpfs_magic = 0;
	__u32 error_flags;

	conf = map_lookup_elem(&tg_conf_map, &zero);
	if (conf) {
		/* Select which cgroup version */
		cgrpfs_magic = conf->cgrp_fs_magic;
		subsys_idx = conf->tg_cgrpv1_subsys_idx;
	}

	task = (struct task_struct *)get_current_task_btf();

	// NB: error_flags are ignored for now
	cgrp = get_task_cgroup(task, cgrpfs_magic, subsys_idx, &error_flags);
	if (!cgrp)
		return 0;

	return get_cgroup_id(cgrp);
}

static inline __attribute__((always_inline)) __u64 tg_get_socket_cgroup_id(struct bpf_sock *sk)
{
	__u64 cgid;

	if (sk) {
		cgid = sk_cgroup_id(sk);
		if (cgid)
			return cgid;
	}

	return tg_sockops_get_current_cgroup_id();
}

int __process_listen_add(struct msg_execve_key *process_key, struct msg_ip_tuple *tuple, __u64 cgid)
{
	struct process_tree_config *cfg;
	int zero = 0;
	uint64_t uid;

	struct listen_endpoint_key key;
	struct listen_endpoint_value *value;

	if (!tuple)
		return 0;
	if (!process_key)
		return 0;

	cfg = map_lookup_elem(&tg_process_tree_config_map, &zero);
	if (!cfg || !cfg->enableProcessTree)
		return 0;

	key.addr[0] = tuple->saddr[0];
	key.addr[1] = tuple->saddr[1];
	key.port = tuple->sport;
	key.wlid = find_my_wlid(cgid);

	value = map_lookup_elem(&tg_h_ps_lstnval, &zero);
	if (!value)
		return 0;

	uid = find_my_self(process_key->pid);
	value->self.uid = uid & 0xffffffff;
	value->self.cpu = uid >> 32;
	tree_id_set_ignore_args(&value->self, false);
	value->accepted = 0;
	value->tx_bytes = 0;
	value->rx_bytes = 0;

	map_update_elem(&listen_endpoint_map, &key, value, BPF_NOEXIST);
	return 0;
}

static __u64 find_key(struct destination_endpoint_key *key, struct msg_ip_tuple *tuple, bool egress)
{
	struct destination_endpoint_value *dest;
	DEBUG_PROCESS("%s: port=%d", __func__, key->port);
	struct destination_endpoint_value *destvalue;
	int exists = 0, zero = 0;
	struct tree_id self;

	if (!key->source)
		return 0;

	if (unlikely(!tuple))
		return 0;

	/* Initial check for exact match. If the entry doesn't exist, we fall back
	 * to increasingly relaxed match conditions.
	 */
	destvalue = map_lookup_elem(&destination_endpoint_map, key);
	if (destvalue && destvalue->deny && (destvalue->deny & TNP_POLICY_REFRESH) == 0)
		return destvalue->deny;
	exists = !!destvalue;

	if (!destvalue) {
		destvalue = map_lookup_elem(&tg_h_ps_dstval, &zero);
		if (!destvalue)
			return 0;

		destvalue->tx_drop_bytes = 0;
		destvalue->tx_default_allow_bytes = 0;
		destvalue->tx_default_drop_bytes = 0;
		destvalue->tx_drop_packets = 0;
		destvalue->tx_default_drop_packets = 0;
		destvalue->tx_default_allow_packets = 0;
		destvalue->rx_drop_bytes = 0;
		destvalue->rx_drop_packets = 0;
		destvalue->rx_default_drop_bytes = 0;
		destvalue->rx_default_drop_packets = 0;
		destvalue->rx_default_allow_bytes = 0;
		destvalue->rx_default_allow_packets = 0;
		destvalue->deny = 0;
		destvalue->tx_bytes = 0;
		destvalue->rx_bytes = 0;
		destvalue->policy = 0;
		destvalue->rule = 0;
		destvalue->sessions = 0;
		destvalue->ipv6 = tuple->ipv6;
		destvalue->ktime_create = tg_get_ktime();
		destvalue->addr_create[0] = tuple->daddr[0];
		destvalue->addr_create[1] = tuple->daddr[1];
		destvalue->port = tuple->dport;
		destvalue->protocol = tuple->proto;
		destvalue->flags = DEST_FLAG_OBSERVATION_DECIDED;
		if (!egress)
			destvalue->flags |= DEST_FLAG_OBSERVED_AT_DESTINATION;
	}

	/* These do not check TNP_POLICY_REFRESH because we only cache keys for
	 * exact matches. Here we have wildcard lookups.
	 */

	/* Try same port but wildcard protocol. Entries programmed without
	 * protocol awareness use protocol=0 to mean "any protocol".
	 */
	key->protocol = 0;
	dest = map_lookup_elem(&destination_endpoint_map, key);
	if (dest && dest->deny) {
		destvalue->policy = dest->policy;
		destvalue->rule = dest->rule;
		destvalue->deny |= (dest->deny | TNP_POLICY_CACHED);
		key->protocol = tuple->proto;
		/* An existing entry takes destvalue in place, but when the value
		 * needs to be created, BPF_NOEXIST stops a racing CPU from
		 * overwriting an entry another CPU just created, so the first
		 * creator's observation point stands.
		 */
		if (!exists)
			map_update_elem(&destination_endpoint_map, key, destvalue, BPF_NOEXIST);
		DEBUG_PROCESS("%s: found policy protocol=0 deny=0x%llx", __func__, dest->deny);
		return dest->deny;
	}
	key->protocol = tuple->proto; // restore

	/* Try with a wildcard port (and protocol). */
	key->port = 0;
	key->protocol = 0;
	dest = map_lookup_elem(&destination_endpoint_map, key);
	if (dest && dest->deny) {
		destvalue->policy = dest->policy;
		destvalue->rule = dest->rule;
		destvalue->deny |= (dest->deny | TNP_POLICY_CACHED);
		key->port = tuple->dport;
		key->protocol = tuple->proto;
		if (!exists)
			map_update_elem(&destination_endpoint_map, key, destvalue, BPF_NOEXIST);
		DEBUG_PROCESS("%s: found policy port=0 deny=0x%llx", __func__, dest->deny);
		return dest->deny;
	}

	/* Restore port and protocol, then try with a wildcard local_id. */
	self = key->local_id;
	key->local_id.uid = 0;
	key->local_id.cpu = 0;
	key->port = tuple->dport;
	key->protocol = tuple->proto;
	dest = map_lookup_elem(&destination_endpoint_map, key);
	if (dest && dest->deny) {
		destvalue->policy = dest->policy;
		destvalue->rule = dest->rule;
		destvalue->deny |= (dest->deny | TNP_POLICY_CACHED);
		key->local_id = self; // restore local_id for caller
		if (!exists)
			map_update_elem(&destination_endpoint_map, key, destvalue, BPF_NOEXIST);
		DEBUG_PROCESS("%s: found policy local_id=0 port=%d deny=0x%llx", __func__, key->port, dest->deny);
		return dest->deny;
	}
	/* wildcard local_id with wildcard protocol (specific port) */
	key->protocol = 0;
	dest = map_lookup_elem(&destination_endpoint_map, key);
	if (dest && dest->deny) {
		destvalue->policy = dest->policy;
		destvalue->rule = dest->rule;
		destvalue->deny |= (dest->deny | TNP_POLICY_CACHED);
		key->local_id = self; // restore local_id for caller
		key->protocol = tuple->proto;
		if (!exists)
			map_update_elem(&destination_endpoint_map, key, destvalue, BPF_NOEXIST);
		DEBUG_PROCESS("%s: found policy local_id=0 protocol=0 port=%d deny=0x%llx", __func__, key->port, dest->deny);
		return dest->deny;
	}
	/* wildcard local_id with wildcard port and protocol */
	key->port = 0;
	dest = map_lookup_elem(&destination_endpoint_map, key);
	key->local_id = self; // restore local_id for caller
	key->port = tuple->dport; // restore port for caller
	key->protocol = tuple->proto; // restore protocol for caller
	if (dest && dest->deny) {
		destvalue->policy = dest->policy;
		destvalue->rule = dest->rule;
		destvalue->deny |= (dest->deny | TNP_POLICY_CACHED);
		if (!exists)
			map_update_elem(&destination_endpoint_map, key, destvalue, BPF_NOEXIST);
		DEBUG_PROCESS("%s: found policy local_id=0 port=0 deny=0x%llx", __func__, dest->deny);
		return dest->deny;
	}
	if (!exists)
		map_update_elem(&destination_endpoint_map, key, destvalue, BPF_NOEXIST);
	return 0;
}

/* Push destkey into socket metadata so future update can avoid the key
 * generation above. Notice because many sockets may have the same destkey
 * this is not necessarily a new entry in the destination_endpoint_map.
 * Further, we complicate our life here a bit because now we have to promote
 * keys to the 'more' correct userspace key if it shows up.
 *
 * Return the verdict code after resolving the sources.
 */
static inline __attribute__((always_inline)) int resolve_key(struct destination_endpoint_key *dnskey,
							     struct destination_endpoint_key *lpmkey,
							     struct destination_endpoint_key *usrkey,
							     struct destination_endpoint_key *destkey,
							     struct msg_ip_tuple *tuple,
							     struct destination_endpoint_key *dst_key,
							     bool egress)
{
	uint64_t dnsv, usrv, destv, lpmv, orv;

	dnsv = find_key(dnskey, tuple, egress);
	lpmv = find_key(lpmkey, tuple, egress);
	usrv = find_key(usrkey, tuple, egress);
	destv = find_key(destkey, tuple, egress);

	orv = (dnsv | lpmv | usrv | destv);
	DEBUG_PROCESS("%s: orv=0x%llx", __func__, orv);
	DEBUG_PROCESS("%s: port=%d", __func__, tuple->dport);

	if (orv & TNP_POLICY_DENY) {
		if (dnsv & TNP_POLICY_DENY) {
			*dst_key = *dnskey;
			return dnsv;
		}
		if (lpmv & TNP_POLICY_DENY) {
			*dst_key = *lpmkey;
			return lpmv;
		}
		if (usrv & TNP_POLICY_DENY) {
			*dst_key = *usrkey;
			return usrv;
		}
		if (destv & TNP_POLICY_DENY) {
			*dst_key = *destkey;
			return destv;
		}
	} else if (orv & TNP_POLICY_ALLOW) {
		if (dnsv & TNP_POLICY_ALLOW) {
			*dst_key = *dnskey;
			return dnsv;
		}
		if (lpmv & TNP_POLICY_ALLOW) {
			*dst_key = *lpmkey;
			return lpmv;
		}
		if (usrv & TNP_POLICY_ALLOW) {
			*dst_key = *usrkey;
			return usrv;
		}
		if (destv & TNP_POLICY_ALLOW) {
			*dst_key = *destkey;
			return destv;
		}
	} else {
		struct destination_endpoint_value *dst_value;
		struct destination_endpoint_key *dfltkey, *updatekey;
		int zero = 0;

		dfltkey = map_lookup_elem(&tg_h_ps_dfltkey, &zero);
		if (!dfltkey)
			return 0;

		/* Small optimization. We could do the default key lookup as
		 * part of find_key() but then we would dup the lookup for
		 * each dst type. So instead of duplicating the lookup do it
		 * once here.
		 */
		dfltkey->destination_id = 0;
		dfltkey->local_id.uid = 0;
		dfltkey->local_id.cpu = 0;
		/* default key ignore_args cleared */
		dfltkey->port = 0;
		dfltkey->protocol = 0;

		/* If there is no explicit policy we want to do accounting
		 * with the most specific dst key. We create a precedence
		 * here: dns, lpm, usr, bpf, dflt.
		 */
		if (dnskey->source) {
			*dst_key = *dnskey;
			updatekey = dnskey;
		} else if (lpmkey->source) {
			*dst_key = *lpmkey;
			updatekey = lpmkey;
		} else if (usrkey->source) {
			*dst_key = *usrkey;
			updatekey = usrkey;
		} else if (destkey->source) {
			*dst_key = *destkey;
			updatekey = destkey;
		} else {
			*dst_key = *dfltkey;
			updatekey = dfltkey;
		}

		/* This also seperates host policy from pod/namespace policy so
		 * that a pod policy will not use default policy from the host.
		 */
		dfltkey->local_nsid = updatekey->local_nsid;
		dfltkey->source = updatekey->source;

		dst_value = map_lookup_elem(&destination_endpoint_map, dfltkey);
		if (dst_value) {
			struct destination_endpoint_value *destvalue;

			destvalue = map_lookup_elem(&destination_endpoint_map, updatekey);
			if (destvalue) {
				destvalue->deny = dst_value->deny | TNP_POLICY_FALLTHRU | TNP_POLICY_CACHED;
				destvalue->policy = dst_value->policy;
				destvalue->rule = dst_value->rule;
				return destvalue->deny;
			}

			destvalue = map_lookup_elem(&tg_h_ps_dstval, &zero);
			if (!destvalue)
				return 0;

			destvalue->ktime_create = tg_get_ktime();
			destvalue->addr_create[0] = tuple->daddr[0];
			destvalue->addr_create[1] = tuple->daddr[1];
			destvalue->ipv6 = tuple->ipv6;
			destvalue->port = tuple->dport;
			destvalue->protocol = tuple->proto;
			destvalue->deny = dst_value->deny | TNP_POLICY_FALLTHRU | TNP_POLICY_CACHED;
			destvalue->tx_bytes = destvalue->rx_bytes = 0;
			destvalue->sessions = 0;
			destvalue->tx_drop_bytes = 0;
			destvalue->tx_default_allow_bytes = 0;
			destvalue->tx_default_drop_bytes = 0;
			destvalue->tx_drop_packets = 0;
			destvalue->tx_default_drop_packets = 0;
			destvalue->tx_default_allow_packets = 0;
			destvalue->rx_drop_bytes = 0;
			destvalue->rx_drop_packets = 0;
			destvalue->rx_default_drop_bytes = 0;
			destvalue->rx_default_drop_packets = 0;
			destvalue->rx_default_allow_bytes = 0;
			destvalue->rx_default_allow_packets = 0;
			destvalue->policy = dst_value->policy;
			destvalue->rule = dst_value->rule;
			destvalue->flags = DEST_FLAG_OBSERVATION_DECIDED;
			if (!egress)
				destvalue->flags |= DEST_FLAG_OBSERVED_AT_DESTINATION;

			map_update_elem(&destination_endpoint_map, updatekey, destvalue, BPF_NOEXIST);
			return dst_value->deny | TNP_POLICY_FALLTHRU;
		}
	}
	return 0;
}

struct destination_endpoint_keys_heap {
	struct destination_endpoint_key dnskey;
	struct destination_endpoint_key lpmkey;
	struct destination_endpoint_key usrkey;
	struct destination_endpoint_key dstkey;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct destination_endpoint_keys_heap);
	__uint(max_entries, 1);
} tg_h_ps_keys SEC(".maps");

/* Decide the observation point of an entry that existed undecided before
 * this packet resolved it, such as a policy template. find_key decides the
 * entries it creates. The CPU whose OR flips DECIDED becomes the sole writer
 * of the direction, and every later packet leaves it alone.
 */
static inline __attribute__((always_inline)) void
mark_observation_point(struct destination_endpoint_key *scratch, struct destination_endpoint_key *dst_key, bool egress)
{
	struct destination_endpoint_value *dest;
	__u64 old;

	/* dst_key points into a socket map value, which the 5.15 and 6.1
	 * verifiers reject as a bpf_map_lookup_elem key. Copy it into the
	 * per-CPU heap scratch, whose pointer they accept (find_key looks up
	 * the same map the same way). A stack copy would work too, but the
	 * cgroup egress program is one stack frame short of the 512 byte
	 * limit, so the key stays off the stack.
	 */
	*scratch = *dst_key;
	dest = map_lookup_elem(&destination_endpoint_map, scratch);
	if (!dest)
		return;

	old = __sync_fetch_and_or(&dest->flags, DEST_FLAG_OBSERVATION_DECIDED);
	if (!(old & DEST_FLAG_OBSERVATION_DECIDED) && !egress)
		__sync_fetch_and_or(&dest->flags, DEST_FLAG_OBSERVED_AT_DESTINATION);
}

static inline __attribute__((always_inline)) int __process_socketmap_add(struct msg_execve_key *process_key, struct destination_endpoint_key *dst_key, struct msg_ip_tuple *tuple, __u64 cgid, bool egress)
{
	struct destination_endpoint_keys_heap *heap_keys;
	struct destination_endpoint_key *dnskey, *lpmkey, *usrkey, *destkey;
	struct process_tree_config *cfg;
	struct msg_execve_key zero_uid;
	struct tree_id self_uid;
	int zero = 0, verdict;
	__u64 *wlid, uid;

	struct endpoint_id_value *value;
	struct endpoint_id_key key;
	struct ip_addr ip_key = {};
	uint64_t lpm_id;

	heap_keys = map_lookup_elem(&tg_h_ps_keys, &zero);
	if (!heap_keys)
		return 0;

	dnskey = &heap_keys->dnskey;
	lpmkey = &heap_keys->lpmkey;
	usrkey = &heap_keys->usrkey;
	destkey = &heap_keys->dstkey;

	if (!dnskey || !lpmkey || !usrkey || !destkey)
		return 0;

	destkey->source = usrkey->source = lpmkey->source = dnskey->source = DESTINATION_SOURCE_UNKNOWN;

	if (!tuple)
		return 0;

	cfg = map_lookup_elem(&tg_process_tree_config_map, &zero);
	if (!cfg || !cfg->enableProcessTree)
		return 0;

	uid = find_my_self(process_key->pid);
	self_uid.uid = uid & 0xffffffff;
	self_uid.cpu = uid >> 32;
	/* preserve ignore_args bit from uid (stored in high bit of cpu) */

	/* Appease the verifier on AKS 5.15.180 kernels I've had trouble with
	 * this recently I think they missed some fixes to verifier or something.
	 */
	dnskey->local_id = lpmkey->local_id = usrkey->local_id = destkey->local_id = self_uid;
	zero_uid.pid = 0;
	memset(&zero_uid.pad, 0, sizeof(zero_uid.pad));
	zero_uid.ktime = 0;

	key.addr[0] = tuple->daddr[0];
	key.addr[1] = tuple->daddr[1];

	// ip_key contains .af_inet6 boolean, when the process tree supports
	// IPv6, we could replace struct endpoint_id_key in each map with struct
	// ip_addr and avoid doing this twice.
	ip_key.addr[0] = tuple->daddr[0];
	ip_key.addr[1] = tuple->daddr[1];
	ip_key.af_inet6 = tuple->ipv6;

	/* Check for DNS generated IDs */
	find_dns_key(dnskey, ip_key);

	// Check for Userspace generated IDs to objects
	value = map_lookup_elem(&tg_endpoint_id_map, &key);
	if (value) {
		usrkey->destination_id = value->id;
		usrkey->source = DESTINATION_SOURCE_USERSPACE;
	}

	lpm_id = lpm_ipkey_lookup(&ip_key);
	if (lpm_id) {
		lpmkey->destination_id = lpm_id;
		lpmkey->source = DESTINATION_SOURCE_USERSPACE;
	}

	// Check for BPF generated IDs
	value = map_lookup_elem(&tg_bpf_endpoint_id_map, &key);
	if (value) {
		destkey->destination_id = value->id;
		destkey->source = DESTINATION_SOURCE_BPF;
	}

	if (usrkey->source > 0 || dnskey->source > 0 || lpmkey->source > 0 || destkey->source > 0)
		goto found_id;

	/* There is no known ID for this IP so lets create one */
	value = map_lookup_elem(&tg_h_ps_epid, &zero);
	if (!value)
		return 0;
	value->id = __sync_fetch_and_add(&glbl_bpf_endpoint_id, 1);
	destkey->destination_id = value->id;
	destkey->source = DESTINATION_SOURCE_BPF;
	map_update_elem(&tg_bpf_endpoint_id_map, &key, value, 0);
found_id:
	dnskey->port = lpmkey->port = usrkey->port = destkey->port = tuple->dport;
	dnskey->protocol = tuple->proto;
	lpmkey->protocol = tuple->proto;
	usrkey->protocol = tuple->proto;
	destkey->protocol = tuple->proto;
	dnskey->local_nsid = lpmkey->local_nsid = usrkey->local_nsid = destkey->local_nsid = 0;

	if (cgid) {
		wlid = map_lookup_elem(&tg_cgid_wlid, &cgid);
		if (wlid)
			dnskey->local_nsid = lpmkey->local_nsid = usrkey->local_nsid = destkey->local_nsid = *wlid;
	}

	verdict = resolve_key(dnskey, lpmkey, usrkey, destkey, tuple, dst_key, egress);
	/* resolve_key has returned, so destkey is free to reuse as the lookup
	 * scratch for the observation point.
	 */
	mark_observation_point(destkey, dst_key, egress);
	return verdict;
}

static inline __attribute__((always_inline)) int process_socketmap_add(struct tcpsocketmap_value *v, struct msg_ip_tuple *tuple)
{
	__u64 cgid;

	cgid = tg_sockops_get_current_cgroup_id();
	/* TCP connect is always the initiator, so this entry is always observed
	 * at the source.
	 */
	return __process_socketmap_add(&v->key, &v->dst_key, tuple, cgid, true);
}

#ifdef PROCESS_TREE
__attribute__((noinline)) int process_socketmap_add_udp(struct udpsocketmap_value *udp, struct msg_ip_tuple *tuple, bool egress)
{
	__u64 cgid;

	cgid = tg_sockops_get_current_cgroup_id();
	/* BPF verifier hint: udp is always non-null here (caller guarantees this).
	 * tg_sockops_get_current_cgroup_id() causes the verifier on kernel 6.8 to
	 * lose the map_value type of callee-saved registers; this guard restores
	 * the non-null proof before udp->key is accessed.
	 */
	if (!udp)
		return 0;
	return __process_socketmap_add(&udp->key, &udp->dst_key, tuple, cgid, egress);
}
#endif

#ifdef PROCESS_TREE
int check_process_socketmap_add(struct tcpsocketmap_value *v, struct msg_ip_tuple *tuple, __u64 cgid)
{
	struct listen_endpoint_key key;
	void *listen;
	__u64 *wlid;

	if (!tuple)
		return 0;

	wlid = map_lookup_elem(&tg_cgid_wlid, &cgid);
	if (wlid)
		key.wlid = *wlid;
	else
		key.wlid = 0;

	key.addr[0] = tuple->saddr[0];
	key.addr[1] = tuple->saddr[1];
	key.port = tuple->sport;

	listen = map_lookup_elem(&listen_endpoint_map, &key);
	if (!listen) {
		key.addr[0] = 0;
		key.addr[1] = 0;

		listen = map_lookup_elem(&listen_endpoint_map, &key);
		if (!listen) {
			/* BPF verifier hint: v is always non-null here (caller guarantees
			 * this). The map_lookup_elem calls above cause the verifier on
			 * kernel 6.8 to lose the map_value type of callee-saved registers;
			 * this guard restores the non-null proof before v->key is accessed.
			 */
			if (!v)
				return 0;
			cgid = 0;
			/* No listen entry matches this established socket, so treat it
			 * as the connecting side, observed at the source.
			 */
			__process_socketmap_add(&v->key, &v->dst_key, tuple, cgid, true);
		}
	}
	return 0;
}
#endif

static int repair_socket_nsid(struct destination_endpoint_key *key, struct bpf_sock *sk)
{
	__u64 cgid, *wlid;

	if (likely(key->local_nsid != 0))
		return 0;

	cgid = tg_get_socket_cgroup_id(sk);
	if (likely(cgid == 0))
		return 0;

	// Otherwise we have CGID, but no local WLID mapping so lets
	// attempt to discover if one exists.
	wlid = map_lookup_elem(&tg_cgid_wlid, &cgid);
	if (wlid) {
		key->local_nsid = *wlid;
		return 1;
	}
	return 0;
}

static inline __attribute__((always_inline)) int process_socketmap_rekey(struct destination_endpoint_key *key, struct __sk_buff *skb)
{
	struct endpoint_id_value *value;
	struct endpoint_id_key idkey;

	if (key->source == DESTINATION_SOURCE_USERSPACE)
		return 0;

	if (skb->protocol != bpf_htons(ETH_P_IPV6)) {
		idkey.addr[0] = skb->remote_ip4;
		idkey.addr[1] = 0;
	} else {
		__u32 l[2];
		__u32 u[2];

		l[0] = skb->remote_ip6[0];
		l[1] = skb->remote_ip6[1];
		u[0] = skb->remote_ip6[2];
		u[1] = skb->remote_ip6[3];

		idkey.addr[0] = (__u64)l;
		idkey.addr[1] = (__u64)u;
	}

	value = map_lookup_elem(&tg_endpoint_id_map, &idkey);
	if (value && value->id != key->destination_id) {
		key->source = DESTINATION_SOURCE_USERSPACE;
		key->destination_id = value->id;
		return 1;
	}
	return 0;
}

/* Encode precedence rules */
static inline __attribute__((always_inline)) int default_policy_verdict(__u64 sum)
{
	if (sum & TNP_POLICY_DENY)
		return TNP_POLICY_DENY;
	if (sum & TNP_POLICY_ALLOW)
		return TNP_POLICY_ALLOW;
	return TNP_POLICY_UNKNOWN;
}

static inline __attribute__((always_inline)) bool is_policy_drop(__u64 sum)
{
	if (sum & TNP_POLICY_ALLOW)
		return false;
	return (sum & TNP_POLICY_DENY);
}

/* Number of packets this skb accounts for.
 *
 * One skb is not one packet at either cgroup hook. On egress the hook runs in
 * ip_finish_output(), before __ip_finish_output() hands a GSO skb to
 * segmentation, so a single skb can be 64KB that leaves as tens of segments.
 * On ingress the hook runs in sk_filter_trim_cap(), after GRO has coalesced
 * received segments into one skb.
 *
 * skb_shinfo(skb)->gso_segs is the count the kernel itself charges for this
 * skb. __tcp_transmit_skb() sets it from tcp_skb_pcount(skb), and adds that
 * same value to tcp_sock->segs_out and to Tcp: OutSegs, a few lines before it
 * hands the skb to ip_queue_xmit(). It is zero on an skb that was never
 * segmented, which is why tcp_segs_in() reads it as max(1, gso_segs) too.
 */
static inline __attribute__((always_inline)) __u64 skb_wire_segments(struct __sk_buff *skb)
{
	__u32 segs = skb->gso_segs;

	return segs ? segs : 1;
}

/* Clear the policy template flag when we have real traffic.
 * Policy entries are created with this flag set to indicate they are
 * templates. When actual traffic flows through, we clear the flag so
 * the entry appears in telemetry.
 */
static inline __attribute__((always_inline)) void clear_policy_template_flag(struct destination_endpoint_value *dest)
{
	if (dest->flags & DEST_FLAG_POLICY_TEMPLATE_ONLY)
		__sync_fetch_and_and(&dest->flags, ~DEST_FLAG_POLICY_TEMPLATE_ONLY);
}

static int send(struct __sk_buff *skb, int deny, struct destination_endpoint_key *key, __u64 len, bool enforce)
{
	struct destination_endpoint_value *dest;
	__u64 segs = skb_wire_segments(skb);

	dest = map_lookup_elem(&destination_endpoint_map, key);
	if (!dest)
		return -1;

	clear_policy_template_flag(dest);

	if (is_policy_drop(deny) && enforce) {
		__sync_fetch_and_add(&dest->tx_drop_bytes, len);
		__sync_fetch_and_add(&dest->tx_drop_packets, segs);
		if (deny & TNP_POLICY_FALLTHRU) {
			__sync_fetch_and_add(&dest->tx_default_drop_bytes, len);
			__sync_fetch_and_add(&dest->tx_default_drop_packets, segs);
		}

		// enforce flag can be removed when UDP supports enforcement
		if ((deny & TNP_POLICY_REJECT) && bpf_ksym_exists(bpf_icmp_send)) {
			if (skb->protocol == bpf_htons(ETH_P_IP))
				bpf_icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PKT_FILTERED);
			else if (skb->protocol == bpf_htons(ETH_P_IPV6))
				bpf_icmp_send(skb, ICMPV6_DEST_UNREACH, ICMPV6_ADM_PROHIBITED);
		}

		return SK_DROP;
	} else if (deny & TNP_POLICY_FALLTHRU) {
		__sync_fetch_and_add(&dest->tx_default_allow_bytes, len);
		__sync_fetch_and_add(&dest->tx_default_allow_packets, segs);
	}

	__sync_fetch_and_add(&dest->tx_bytes, len);
	return SK_PASS;
}

/* enforce is true only on paths where a policy drop actually drops the packet. */
static int recv(struct __sk_buff *skb, int deny, struct destination_endpoint_key *key, __u64 len, bool enforce)
{
	struct destination_endpoint_value *dest;
	__u64 segs = skb_wire_segments(skb);

	dest = map_lookup_elem(&destination_endpoint_map, key);
	if (!dest)
		return -1;

	clear_policy_template_flag(dest);

	/* An enforced drop never reaches the socket, so leave its bytes out of
	 * rx_bytes, the way send() leaves an enforced drop out of tx_bytes.
	 */
	if (is_policy_drop(deny) && enforce) {
		__sync_fetch_and_add(&dest->rx_drop_bytes, len);
		__sync_fetch_and_add(&dest->rx_drop_packets, segs);
		if (deny & TNP_POLICY_FALLTHRU) {
			__sync_fetch_and_add(&dest->rx_default_drop_bytes, len);
			__sync_fetch_and_add(&dest->rx_default_drop_packets, segs);
		}
		return SK_DROP;
	}

	__sync_fetch_and_add(&dest->rx_bytes, len);

	/* A non-enforced (UDP) drop still lands, so its bytes count above. The
	 * verdict the caller discards stays a drop.
	 */
	if (is_policy_drop(deny))
		return SK_DROP;

	if (deny & TNP_POLICY_FALLTHRU) {
		__sync_fetch_and_add(&dest->rx_default_allow_bytes, len);
		__sync_fetch_and_add(&dest->rx_default_allow_packets, segs);
	}

	return SK_PASS;
}

/* Return the policy generation, which userspace bumps on every datapath record
 * change. The counter increases monotonically over the Tetragon agent's
 * lifetime.
 */
static inline __attribute__((always_inline)) __u32 current_policy_gen(void)
{
	struct process_tree_config *cfg;
	int zero = 0;

	cfg = map_lookup_elem(&tg_process_tree_config_map, &zero);
	if (!cfg)
		return 0;
	return cfg->policy_generation;
}

/* Report whether the socket's cached verdict is from an older policy generation.
 * The caller stamps the current generation after it writes the new verdict.
 * Stamping here instead would let a concurrent CPU on the shared socket map read
 * the advanced generation before v->deny is updated and use the stale verdict.
 */
static inline __attribute__((always_inline)) bool policy_gen_stale(struct tcpsocketmap_value *v)
{
	return v->policy_gen != current_policy_gen();
}

/* Stats and deny/allow decisions are made in a sequence each step
 * loosens the key searching for a higher level rule. The order of
 * this search is important and is done in the following order.
 *
 * Order of operations:
 *
 * local_id + wlid + l3(destination_id) + l4(port)   : dest_full
 * local_id + wlid + l3(destination_id)              : dest_port
 *            wlid + l3(destination_id)              : dest_local
 *            wlid                                   : default
 */
static inline __attribute__((always_inline)) int process_socketmap_send(struct tcpsocketmap_value *v, struct __sk_buff *skb)
{
	__u64 cgid, gen, len = skb->len;
	int verdict, rewrite;

	/* These are incomplete keys the result of process and sessions taht
	 * existed before Tetragon started. We may add support for these flows
	 * in the future for now we just pass them along.
	 */
	if (!v->dst_key.source)
		return SK_PASS;

	rewrite = repair_socket_nsid(&v->dst_key, skb->sk);
	rewrite |= process_socketmap_rekey(&v->dst_key, skb);
	rewrite |= policy_gen_stale(v);
	if (!rewrite) {
		verdict = send(skb, v->deny, &v->dst_key, len, true);
		if (verdict < 0)
			goto err_out;
		return verdict;
	}
err_out:
	/* Capture the generation before the resolve and stamp it after v->deny, so
	 * the stamp is never newer than the verdict and a concurrent CPU sees the
	 * verdict first. On a weakly-ordered arch (arm64) the two stores can still be
	 * observed out of order, so a racing CPU may use the stale verdict for the
	 * packets in flight during one re-resolve. The leak self-heals, and closing
	 * it is out of scope here.
	 */
	gen = current_policy_gen();
	cgid = tg_get_socket_cgroup_id(skb->sk);
	/* A TCP entry belongs to the connecting side, so it is observed at the
	 * source. check_process_socketmap_add assumes the same for an
	 * established socket with no matching listen entry.
	 */
	v->deny = __process_socketmap_add(&v->key, &v->dst_key, &v->tuple, cgid, true);
	v->policy_gen = gen;
	verdict = send(skb, v->deny, &v->dst_key, len, true);
	if (verdict < 0)
		return SK_PASS;
	return verdict;
}

/* Stats and deny/allow decisions are made in a sequence each step
 * loosens the key searching for a higher level rule. The order of
 * this search is important and is done in the following order.
 *
 * Order of operations:
 *
 * local_id + wlid + l3(destination_id) + l4(port)
 * local_id + wlid + l3(destination_id)
 *            wlid + l3(destination_id)
 *            wlid
 */
static inline __attribute__((always_inline)) int process_socketmap_recv(struct tcpsocketmap_value *v, struct __sk_buff *skb)
{
	__u64 cgid, gen, len = skb->len;
	int verdict, rewrite;

	/* Same as above see note in _send. */
	if (!v->dst_key.source)
		return SK_PASS;

	rewrite = repair_socket_nsid(&v->dst_key, skb->sk);
	rewrite |= process_socketmap_rekey(&v->dst_key, skb);
	rewrite |= policy_gen_stale(v);
	if (!rewrite) {
		verdict = recv(skb, v->deny, &v->dst_key, len, true);
		if (verdict < 0)
			goto err_out;
		return verdict;
	}
err_out:
	/* See the ordering note in process_socketmap_send. */
	gen = current_policy_gen();
	cgid = tg_get_socket_cgroup_id(skb->sk);
	/* A TCP entry belongs to the connecting side, so it is observed at the
	 * source. check_process_socketmap_add assumes the same for an
	 * established socket with no matching listen entry.
	 */
	v->deny = __process_socketmap_add(&v->key, &v->dst_key, &v->tuple, cgid, true);
	v->policy_gen = gen;
	verdict = recv(skb, v->deny, &v->dst_key, len, true);
	if (verdict < 0)
		return SK_PASS;
	return verdict;
}

#endif // __PROCESS_TREE_H__
