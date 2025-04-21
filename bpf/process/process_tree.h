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

#include "parsers/dns/pstree.h"

struct process_tree_config {
	uint64_t enableProcessTree;
	uint64_t bpfGenIds;
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

static int atomic_xchg(__u64 *cnt, __u64 val)
{
	return __atomic_exchange_n(cnt, val, __ATOMIC_SEQ_CST);
}

static struct tree_id get_new_tree_id()
{
	u32 zero = 0;
	u64 *counter;
	struct tree_id id;

	counter = map_lookup_elem(&tg_tree_id, &zero);
	if (!counter) {
		id.uid = 0;
		return id;
	}

	id.uid = ++(*counter);
	id.cpu = get_smp_processor_id();
	DEBUG("ID: %d.%d\n", id.cpu, id.uid);
	return id;
}

char global_zero[MAXARGLENGTH] = { 0 };

int __insert_process_tree(__u32 pid, __u64 cgid)
{
	struct process_tree_binary_uid_key *tree_key;
	struct process_tree_key *k, local = { 0 }, *parent;
	struct process_tree_config *cfg;
	struct process_tree_value *old;
	struct execve_map_value *curr;
	struct tree_id id, *self_uid;
	__u64 zero = 0;
	__u64 *nsid;

	cfg = map_lookup_elem(&tg_process_tree_config_map, &zero);
	if (!cfg || !cfg->enableProcessTree)
		return 0;

	curr = execve_map_get_noinit(pid);
	if (!curr)
		return 0;

	tree_key = map_lookup_elem(&process_tree_binary_uid_key_map, &zero);
	if (!tree_key)
		return 0;

	// Process UID is done in the following order. First check if there
	// is a binary key with empty args. This is needed for policy that
	// does not specify args. Next lookup the fully qualified process
	// with args key. And finally generate an ID.
	probe_read_kernel(&tree_key->binary, BINARY_PATH_MAX_LEN, curr->bin.path);
	probe_read_kernel(&tree_key->args, MAXARGLENGTH, global_zero);
	self_uid = map_lookup_elem(&process_tree_binary_uid_map, tree_key);
	if (!self_uid) {
		probe_read_kernel(&tree_key->args, MAXARGLENGTH, curr->bin.args);
		self_uid = map_lookup_elem(&process_tree_binary_uid_map, tree_key);
	}

	if (self_uid) {
		id = *self_uid;
	} else {
		id = get_new_tree_id();
		if (!id.uid)
			return 0;
		map_update_elem(&process_tree_uid_binary_map, &id, tree_key, 0);
		map_update_elem(&process_tree_binary_uid_map, tree_key, &id, 0);
	}
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
		k->path[0].uid = 0;
		k->path[1].uid = 0;
		k->path[2].uid = 0;
		k->path[3].uid = 0;
		k->path[4].uid = 0;
		k->path[5].uid = 0;
		k->path[6].uid = 0;
		k->path[7].uid = 0;
	}

	k->self = id;
	map_update_elem(&tg_ee_pid_data, &pid, &local, 0);

	nsid = map_lookup_elem(&tg_cgroup_namespace_map, &cgid);
	if (nsid)
		k->nsid = *nsid;
	else
		k->nsid = 0;

	DEBUG("curr->nspid=%d curr->key.pid=%d", curr->nspid, curr->key.pid);

	old = map_lookup_elem(&process_tree_map, k);
	if (!old) {
		old = map_lookup_elem(&process_tree_value_heap, &zero);
		if (!old)
			return 0;

		old->in_init_tree = curr->flags & EVENT_IN_INIT_TREE;
		old->in_container = curr->nspid != 0;
		old->ktime_last_exec = ktime_get_ns();
		old->ktime_first_exec = ktime_get_ns();
		map_update_elem(&process_tree_map, k, old, 0);
	} else {
		// Duplicating ktime sets in both branches to help verifier and
		// clang generate code that play well together. Otherwise we lose
		// old != NULL on some kernels.
		old->in_init_tree = curr->flags & EVENT_IN_INIT_TREE;
		old->in_container = curr->nspid != 0;
		old->ktime_last_exec = ktime_get_ns();
	}
	return 0;
}

int insert_process_tree(void)
{
	int err = 0;
#if defined(__V511_BPF_PROG) || defined(__V60_BPF_PROG) || defined(__V61_BPF_PROG) || defined(__V63_BPF_PROG) || defined(__V611_BPF_PROG)
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

int __process_listen_add(struct tcpsocketmap_value *v, struct msg_ip_tuple *tuple, __u64 cgid)
{
	struct process_tree_config *cfg;
	struct msg_execve_key zero_uid;
	struct execve_map_value *curr;
	struct tree_id *self_uid;
	int zero = 0;
	__u64 *nsid;

	struct listen_endpoint_key key;
	struct listen_endpoint_value *value;

	if (!tuple)
		return 0;
	if (!v)
		return 0;

	cfg = map_lookup_elem(&tg_process_tree_config_map, &zero);
	if (!cfg || !cfg->enableProcessTree)
		return 0;

	curr = execve_map_get_noinit(v->key.pid);
	if (!curr)
		return 0;

	struct process_tree_binary_uid_key *tree_key;

	tree_key = map_lookup_elem(&process_tree_binary_uid_key_map, &zero);
	if (!tree_key)
		return 0;
	probe_read_kernel(&tree_key->binary, BINARY_PATH_MAX_LEN, curr->bin.path);
	probe_read_kernel(&tree_key->args, MAXARGLENGTH, curr->bin.args);
	self_uid = map_lookup_elem(&process_tree_binary_uid_map, tree_key);
	if (!self_uid)
		return 0;

	zero_uid.pid = 0;
	memset(&zero_uid.pad, 0, sizeof(zero_uid.pad));
	zero_uid.ktime = 0;

	key.addr[0] = tuple->saddr[0];
	key.addr[1] = tuple->saddr[1];
	key.port = tuple->sport;
	key.nsid = 0;

	nsid = map_lookup_elem(&tg_cgroup_namespace_map, &cgid);
	if (nsid)
		key.nsid = *nsid;

	value = map_lookup_elem(&listen_endpoint_heap, &zero);
	if (!value)
		return 0;
	value->self = *self_uid;
	value->accepted = 0;
	value->tx_bytes = 0;
	value->rx_bytes = 0;

	map_update_elem(&listen_endpoint_map, &key, value, BPF_NOEXIST);
	return 0;
}

static inline __attribute__((always_inline)) int __process_socketmap_add(struct tcpsocketmap_value *v, struct msg_ip_tuple *tuple, __u64 cgid)
{
	struct destination_endpoint_key destkey;
	struct destination_endpoint_value *dest;
	struct process_tree_config *cfg;
	struct msg_execve_key zero_uid;
	struct execve_map_value *curr;
	struct tree_id *self_uid;
	int zero = 0;
	__u64 *nsid;

	struct endpoint_id_key key;
	struct ip_addr ip_key = {};
	struct endpoint_id_value *value;
	struct dns_endpoint_id_value *dns_value;

	if (!tuple)
		return 0;

	if (!v)
		return 0;

	cfg = map_lookup_elem(&tg_process_tree_config_map, &zero);
	if (!cfg || !cfg->enableProcessTree)
		return 0;

	curr = execve_map_get_noinit(v->key.pid);
	if (!curr)
		return 0;

	struct process_tree_binary_uid_key *tree_key;
	tree_key = map_lookup_elem(&process_tree_binary_uid_key_map, &zero);
	if (!tree_key)
		return 0;
	probe_read_kernel(&tree_key->binary, BINARY_PATH_MAX_LEN, curr->bin.path);
	probe_read_kernel(&tree_key->args, MAXARGLENGTH, global_zero);
	self_uid = map_lookup_elem(&process_tree_binary_uid_map, tree_key);
	if (!self_uid) {
		probe_read_kernel(&tree_key->args, MAXARGLENGTH, curr->bin.args);
		self_uid = map_lookup_elem(&process_tree_binary_uid_map, tree_key);
		if (!self_uid)
			return 0;
	}

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

	// destination precedence DNS, Userspace (service, pods), BPF generated ID.
	dns_value = map_lookup_elem(&tg_dns_endpoint_id_map, &ip_key);
	if (dns_value) {
		destkey.destination_id = dns_value->id;
		destkey.source = dns_value->source;
	} else {
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
	}

	destkey.local_id = *self_uid;
	destkey.port = tuple->dport;
	destkey.local_nsid = 0;

	if (cgid) {
		nsid = map_lookup_elem(&tg_cgroup_namespace_map, &cgid);
		if (nsid)
			destkey.local_nsid = *nsid;
	}

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
		destvalue->ipv6 = tuple->ipv6;
		destvalue->port = tuple->dport;
		destvalue->deny = 0;
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
		else if (dest->deny == 1) {
			// fixup process entry
			destkey.port = tuple->dport;
			map_update_elem(&destination_endpoint_map, &destkey, destvalue, 0);
			return 1;
		}

		destkey.local_id.uid = 0;
		destkey.local_id.cpu = 0;
		dest = map_lookup_elem(&destination_endpoint_map, &destkey);
		if (!dest)
			map_update_elem(&destination_endpoint_map, &destkey, destvalue, 0);
		else if (dest->deny == 1) {
			// fixup local state this is dumb
			destkey.local_id = *self_uid;
			destkey.port = tuple->dport;
			map_update_elem(&destination_endpoint_map, &destkey, destvalue, 0);
			return 1;
		}
	} else {
		if (dest->deny)
			return 1;
	}

	return 0;
}

static inline __attribute__((always_inline)) int process_socketmap_add(struct tcpsocketmap_value *v, struct msg_ip_tuple *tuple)
{
	__u64 cgid;

	cgid = tg_sockops_get_current_cgroup_id();
	return __process_socketmap_add(v, tuple, cgid);
}

int check_process_socketmap_add(struct tcpsocketmap_value *v, struct msg_ip_tuple *tuple, __u64 cgid)
{
	struct listen_endpoint_key key;
	void *listen;
	__u64 *nsid;

	if (!tuple)
		return 0;

	nsid = map_lookup_elem(&tg_cgroup_namespace_map, &cgid);
	if (nsid)
		key.nsid = *nsid;
	else
		key.nsid = 0;

	key.addr[0] = tuple->saddr[0];
	key.addr[1] = tuple->saddr[1];
	key.port = tuple->sport;

	listen = map_lookup_elem(&listen_endpoint_map, &key);
	if (!listen) {
		key.addr[0] = 0;
		key.addr[1] = 0;

		listen = map_lookup_elem(&listen_endpoint_map, &key);
		if (!listen) {
			cgid = 0;
			__process_socketmap_add(v, tuple, cgid);
		}
	}
	return 0;
}

static inline __attribute__((always_inline)) int process_socketmap_rekey(struct destination_endpoint_key *key, struct __sk_buff *skb)
{
	struct endpoint_id_value *value;
	struct endpoint_id_key idkey;

	if (key->destination_id == DESTINATION_SOURCE_USERSPACE)
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

static inline __attribute__((always_inline)) int dest_policy(__u64 *p, __u64 len, struct destination_endpoint_value *v)
{
	*p |= v->deny;
	if (is_policy_drop(*p))
		return SK_DROP;
	return SK_PASS;
}

/* Stats and deny/allow decisions are made in a sequence each step
 * loosens the key searching for a higher level rule. The order of
 * this search is important and is done in the following order.
 *
 * Order of operations:
 *
 * local_id + nsid + l3(destination_id) + l4(port)   : dest_full
 * local_id + nsid + l3(destination_id)              : dest_port
 *            nsid + l3(destination_id)              : dest_local
 *            nsid                                   : default
 */
static inline __attribute__((always_inline)) int process_socketmap_send(struct tcpsocketmap_value *v, struct __sk_buff *skb)
{
	struct destination_endpoint_value *dest_full, *dest_port, *dest_local, *dest_default, dummy = { 0 };
	struct destination_endpoint_key key;
	__u64 policy = 0, quota, now;
	__u64 len = skb->len;
	int verdict;

	/* These are incomplete keys the result of process and sessions taht
	 * existed before Tetragon started. We may add support for these flows
	 * in the future for now we just pass them along.
	 */
	if (!v->dst_key.source)
		return SK_PASS;

	process_socketmap_rekey(&v->dst_key, skb);

	key = v->dst_key;
	dest_full = map_lookup_elem(&destination_endpoint_map, &key);
	if (dest_full) {
		__sync_fetch_and_add(&dest_full->tx_bytes, len);
		verdict = dest_policy(&policy, len, dest_full);
		if (verdict == SK_DROP)
			__sync_fetch_and_add(&dest_full->tx_drops, len);
	} else {
		dest_full = &dummy;
	}

	/* Also update the per dst entry */
	key = v->dst_key;
	key.port = 0;
	dest_port = map_lookup_elem(&destination_endpoint_map, &key);
	if (dest_port) {
		__sync_fetch_and_add(&dest_port->tx_bytes, len);
		verdict = dest_policy(&policy, len, dest_port);
		if (verdict == SK_DROP) {
			__sync_fetch_and_add(&dest_full->tx_drops, len);
			__sync_fetch_and_add(&dest_port->tx_drops, len);
		}
	} else {
		dest_port = &dummy;
	}

	key.local_id.uid = 0;
	key.local_id.cpu = 0;
	dest_local = map_lookup_elem(&destination_endpoint_map, &key);
	if (dest_local) {
		__sync_fetch_and_add(&dest_local->tx_bytes, len);
		verdict = dest_policy(&policy, len, dest_local);
		if (verdict == SK_DROP) {
			__sync_fetch_and_add(&dest_full->tx_drops, len);
			__sync_fetch_and_add(&dest_port->tx_drops, len);
			__sync_fetch_and_add(&dest_local->tx_drops, len);
		}

		/* This is all a bit racy, but if you are surfing on the edge of a
		 * time window the observer can't tell order of operations between
		 * two skbs and they can't measure time well enough to know if I did
		 * it 100% correctly. All this is write_once so values are not going
		 * to be corrupted.
		 */
		now = ktime_get_ns();
		if (dest_local->ktime_tx_reset && (now - dest_local->ktime_last_reset > dest_local->ktime_tx_reset)) {
			atomic_xchg(&dest_local->tx_quota, 0);
			atomic_xchg(&dest_local->ktime_last_reset, now);
		}

		quota = __sync_add_and_fetch(&dest_local->tx_quota, len);
		if (dest_local->tx_limit && quota > dest_local->tx_limit) {
			__sync_fetch_and_add(&dest_full->tx_drops, len);
			__sync_fetch_and_add(&dest_port->tx_drops, len);
			__sync_fetch_and_add(&dest_local->tx_drops, len);
			return SK_DROP;
		}
	} else {
		dest_local = &dummy;
	}

	/* We put this below the quota support because legacy quota policy
	 * does not push a default rule and we hit the !dest case.
	 */
	verdict = default_policy_verdict(policy);
	if (verdict != TNP_POLICY_UNKNOWN)
		goto out;

	/* If there is no specific verdict allow or deny from above we
	 * check pod specific wildcard rule. This acts as a catch all.
	 */
	key.destination_id = 0;
	dest_default = map_lookup_elem(&destination_endpoint_map, &key);
	if (dest_default) {
		__sync_fetch_and_add(&dest_default->tx_bytes, len);
		verdict = dest_policy(&policy, len, dest_default);
		if (verdict == SK_DROP) {
			__sync_fetch_and_add(&dest_full->tx_drops, len);
			__sync_fetch_and_add(&dest_port->tx_drops, len);
			__sync_fetch_and_add(&dest_local->tx_drops, len);
			__sync_fetch_and_add(&dest_default->tx_drops, len);
		}
	}
out:
	if (is_policy_drop(policy))
		return SK_DROP;

	return SK_PASS;
}

/* Stats and deny/allow decisions are made in a sequence each step
 * loosens the key searching for a higher level rule. The order of
 * this search is important and is done in the following order.
 *
 * Order of operations:
 *
 * local_id + nsid + l3(destination_id) + l4(port)
 * local_id + nsid + l3(destination_id)
 *            nsid + l3(destination_id)
 *            nsid
 */
static inline __attribute__((always_inline)) int process_socketmap_recv(struct tcpsocketmap_value *v, struct __sk_buff *skb)
{
	struct destination_endpoint_value *dest_full, *dest_port, *dest_local, *dest_default;
	struct destination_endpoint_key key;
	__u64 len = skb->len;
	__u64 policy = 0;
	int verdict;

	/* Same as above see note in _send. */
	if (!v->dst_key.source)
		return SK_PASS;

	process_socketmap_rekey(&v->dst_key, skb);
	dest_full = map_lookup_elem(&destination_endpoint_map, &v->dst_key);
	if (dest_full) {
		__sync_fetch_and_add(&dest_full->rx_bytes, len);
		verdict = dest_policy(&policy, len, dest_full);
		if (verdict == SK_DROP)
			__sync_fetch_and_add(&dest_full->tx_drops, len);
	}

	/* Also update the per dst entry */
	key = v->dst_key;
	key.port = 0;
	dest_port = map_lookup_elem(&destination_endpoint_map, &key);
	if (dest_port) {
		__sync_fetch_and_add(&dest_port->rx_bytes, len);
		verdict = dest_policy(&policy, len, dest_port);
		if (verdict == SK_DROP)
			__sync_fetch_and_add(&dest_port->tx_drops, len);
	}

	key.local_id.uid = 0;
	key.local_id.cpu = 0;
	dest_local = map_lookup_elem(&destination_endpoint_map, &key);
	if (dest_local) {
		__sync_fetch_and_add(&dest_local->rx_bytes, len);
		verdict = dest_policy(&policy, len, dest_local);
		if (verdict == SK_DROP)
			__sync_fetch_and_add(&dest_local->tx_drops, len);
	}

	/* We put this below the quota support because legacy quota policy
	 * does not push a default rule and we hit the !dest case.
	 */
	verdict = default_policy_verdict(policy);
	if (verdict != TNP_POLICY_UNKNOWN)
		goto out;

	/* If there is no specific verdict allow or deny from above we
	 * check pod specific wildcard rule. This acts as a catch all.
	 */
	key.destination_id = 0;
	dest_default = map_lookup_elem(&destination_endpoint_map, &key);
	if (dest_default) {
		__sync_fetch_and_add(&dest_default->rx_bytes, len);
		dest_policy(&policy, len, dest_default);
		if (verdict == SK_DROP)
			__sync_fetch_and_add(&dest_default->tx_drops, len);
	}
out:
	if (is_policy_drop(policy))
		return SK_DROP;

	return SK_PASS;
}

#endif // __PROCESS_TREE_H__
