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
#include "networking/l3/tcp/bpf_tcp_info.h"

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

static int atomic_xchg(__u64 *cnt, __u64 val)
{
	return __atomic_exchange_n(cnt, val, __ATOMIC_SEQ_CST);
}

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
				   curr->bin.path);
	if (!self_uid) {
		map_update_elem(&process_tree_uid_binary_map,
				&curr->key, &curr->bin.path, 0);
		map_update_elem(&process_tree_binary_uid_map,
				curr->bin.path, &curr->key, 0);
		self_uid = &curr->key;
	}

	struct msg_execve_key zero_uid;

	zero_uid.pid = 0;
	memset(&zero_uid.pad, 0, sizeof(zero_uid.pad));
	zero_uid.ktime = 0;

	parent = event_find_parent();
	if (!parent) {
		parent_uid = &zero_uid;
	} else {
		parent_uid = map_lookup_elem(&process_tree_binary_uid_map, parent->bin.path);
		if (!parent_uid)
			parent_uid = &zero_uid;
	}

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
	return 0;
}

uint64_t glbl_bpf_endpoint_id = 1;

static inline __attribute__((always_inline)) int process_socketmap_add(struct tcpsocketmap_value *v, struct msg_ip_tuple *tuple)
{
	struct msg_execve_key *self_uid, *parent_uid;
	struct destination_endpoint_key destkey;
	struct destination_endpoint_value *dest;
	struct process_tree_config *cfg;
	struct execve_map_value *parent;
	struct msg_execve_key zero_uid;
	struct execve_map_value *curr;
	__u64 cgid, *nsid;
	int zero = 0;

	struct endpoint_id_key key;
	struct endpoint_id_value *value;

	if (!v)
		return 0;

	cfg = map_lookup_elem(&tg_process_tree_config_map, &zero);
	if (!cfg || !cfg->enableProcessTree)
		return 0;

	curr = execve_map_get_noinit(v->key.pid);
	if (!curr)
		return 0;

	self_uid = map_lookup_elem(&process_tree_binary_uid_map, curr->bin.path);
	if (!self_uid)
		return 0;

	zero_uid.pid = 0;
	memset(&zero_uid.pad, 0, sizeof(zero_uid.pad));
	zero_uid.ktime = 0;

	parent = event_find_parent();
	if (!parent) {
		parent_uid = &zero_uid;
	} else {
		parent_uid = map_lookup_elem(&process_tree_binary_uid_map, parent->bin.path);
		if (!parent_uid)
			parent_uid = &zero_uid;
	}

	key.addr[0] = tuple->daddr[0];
	key.addr[1] = tuple->daddr[1];

	// destination_id verifier fix to if/else;
	value = map_lookup_elem(&tg_endpoint_id_map, &key);
	if (!value) {
		if (!cfg->bpfGenIds)
			return 0;

		destkey.source = DESTINATION_SOURCE_BPF;
		value = map_lookup_elem(&tg_bpf_endpoint_id_map, &key);
		if (!value) {
			value = map_lookup_elem(&tg_bpf_endpoint_id_heap, &zero);
			if (!value)
				return 0;
			value->id = __sync_fetch_and_add(&glbl_bpf_endpoint_id, 1);
			destkey.destination_id = value->id;
			map_update_elem(&tg_bpf_endpoint_id_map, &key, value, 0);
		} else {
			destkey.destination_id = value->id;
		}
	} else {
		destkey.destination_id = value->id;
		destkey.source = DESTINATION_SOURCE_USERSPACE;
	}

	destkey.process_id.self = *self_uid;
	destkey.process_id.parent = *parent_uid;
	destkey.port = tuple->dport;

	cgid = tg_get_current_cgroup_id();
	nsid = map_lookup_elem(&tg_cgroup_namespace_map, &cgid);
	if (nsid)
		destkey.process_id.nsid = *nsid;
	else
		destkey.process_id.nsid = 0;

	/* Push destkey into socket metadata so future update can avoid
	 * the key generation above. Notice because many sockets may have
	 * the same destkey this is not necessarily a new entry in the
	 * destination_endpoint_map. Further we complicate our life here
	 * a bit because now we have to promote keys to the 'more' correct
	 * userspace key if it shows up.
	 */
	v->dst_key = destkey;

	dest = map_lookup_elem(&destination_endpoint_map, &destkey);
	if (!dest) {
		struct destination_endpoint_value *destvalue;

		destvalue = map_lookup_elem(&destination_endpoint_heap, &zero);
		if (!destvalue)
			return 0;

		destvalue->ktime_create = ktime_get_ns();
		destvalue->addr_create[0] = tuple->daddr[0];
		destvalue->addr_create[1] = tuple->daddr[1];
		destvalue->port = tuple->dport;
		destvalue->tx_quota = destvalue->tx_limit = 0;
		destvalue->tx_bytes = destvalue->rx_bytes = 0;
		map_update_elem(&destination_endpoint_map, &destkey, destvalue, 0);
		/* If there is a dest.port entry then we previously also
		 * add the dest.port=0 entry so we only need to check this
		 * on new dest entries.
		 */
		destkey.port = 0;
		destvalue->port = 0;
		dest = map_lookup_elem(&destination_endpoint_map, &destkey);
		if (!dest)
			map_update_elem(&destination_endpoint_map, &destkey, destvalue, 0);

		destkey.process_id.self.pid = 0;
		destkey.process_id.self.ktime = 0;
		destkey.process_id.parent.pid = 0;
		destkey.process_id.parent.ktime = 0;
		dest = map_lookup_elem(&destination_endpoint_map, &destkey);
		if (!dest)
			map_update_elem(&destination_endpoint_map, &destkey, destvalue, 0);
	}

	return 0;
}

static inline __attribute__((always_inline)) int process_socketmap_rekey(struct destination_endpoint_key *key, struct __sk_buff *skb)
{
	struct endpoint_id_value *value;
	struct endpoint_id_key idkey;

	if (skb->family != AF_INET6) {
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
	}
	return 0;
}

static inline __attribute__((always_inline)) int process_socketmap_send(struct tcpsocketmap_value *v, struct __sk_buff *skb)
{
	struct destination_endpoint_value *dest;
	struct destination_endpoint_key key;
	__u64 len, quota, now;

	/* These are incomplete keys the result of process and sessions taht
	 * existed before Tetragon started. We may add support for these flows
	 * in the future for now we just pass them along.
	 */
	if (!v->dst_key.source)
		return SK_PASS;

	process_socketmap_rekey(&v->dst_key, skb);
	dest = map_lookup_elem(&destination_endpoint_map, &v->dst_key);
	if (!dest)
		return SK_PASS;
	len = skb->len;
	__sync_fetch_and_add(&dest->tx_bytes, len);

	/* Also update the per dst entry */
	key = v->dst_key;
	key.port = 0;
	dest = map_lookup_elem(&destination_endpoint_map, &key);
	if (!dest)
		return SK_PASS;
	__sync_fetch_and_add(&dest->tx_bytes, len);

	key.process_id.self.pid = 0;
	key.process_id.self.ktime = 0;
	key.process_id.parent.pid = 0;
	key.process_id.parent.ktime = 0;
	dest = map_lookup_elem(&destination_endpoint_map, &key);
	if (!dest)
		return SK_PASS;
	__sync_fetch_and_add(&dest->tx_bytes, len);

	/* This is all a bit racy, but if you are surfing on the edge of a
	 * time window the observer can't tell order of operations between
	 * two skbs and they can't measure time well enough to know if I did
	 * it 100% correctly. All this is write_once so values are not going
	 * to be corrupted.
	 */
	now = ktime_get_ns();
	if (dest->ktime_tx_reset && (now - dest->ktime_last_reset > dest->ktime_tx_reset)) {
		atomic_xchg(&dest->tx_quota, 0);
		atomic_xchg(&dest->ktime_last_reset, now);
	}

	quota = __sync_fetch_and_add(&dest->tx_quota, len);
	if (dest->tx_limit && quota > dest->tx_limit) {
		__sync_fetch_and_add(&dest->tx_drops, len);
		return SK_DROP;
	}

	return SK_PASS;
}

static inline __attribute__((always_inline)) int process_socketmap_recv(struct tcpsocketmap_value *v, struct __sk_buff *skb)
{
	struct destination_endpoint_value *dest;
	struct destination_endpoint_key key;
	__u64 len;

	/* Same as above see note in _send. */
	if (!v->dst_key.source)
		return SK_PASS;

	process_socketmap_rekey(&v->dst_key, skb);
	dest = map_lookup_elem(&destination_endpoint_map, &v->dst_key);
	if (!dest)
		return SK_PASS;
	len = skb->len;
	__sync_fetch_and_add(&dest->rx_bytes, len);

	/* Also update the per dst entry */
	key = v->dst_key;
	key.port = 0;
	dest = map_lookup_elem(&destination_endpoint_map, &key);
	if (!dest)
		return SK_PASS;
	__sync_fetch_and_add(&dest->rx_bytes, len);

	key.process_id.self.pid = 0;
	key.process_id.self.ktime = 0;
	key.process_id.parent.pid = 0;
	key.process_id.parent.ktime = 0;
	dest = map_lookup_elem(&destination_endpoint_map, &key);
	if (!dest)
		return SK_PASS;
	__sync_fetch_and_add(&dest->rx_bytes, len);

	return SK_PASS;
}

#endif // __PROCESS_TREE_H__
