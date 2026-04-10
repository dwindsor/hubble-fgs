struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 64 * 1024);
	__type(key, struct addr4_lpm_trie);
	__type(value, struct lpm_endpoint_id_value);
} addr4lpm_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 64 * 1024);
	__type(key, struct addr6_lpm_trie);
	__type(value, struct lpm_endpoint_id_value);
} addr6lpm_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct cfg_value);
	__uint(max_entries, 1);
} tg_l3_cfg SEC(".maps");

struct ip_addr {
	uint64_t addr[2];
	uint8_t af_inet6;
	uint8_t pad[7];
};

static uint64_t glbl_bpf_endpoint_id = 1;

FUNC_INLINE uint64_t lpm_ipkey_lookup(struct ip_addr *ip_key)
{
	struct lpm_endpoint_id_value *val;

	if (!ip_key)
		return 0;

	if (ip_key->af_inet6) {
		struct addr6_lpm_trie key = { 0 };

		key.prefix = 128;
		memcpy(key.addr, ip_key->addr, sizeof(key.addr));
		val = bpf_map_lookup_elem(&addr6lpm_map, &key);
	} else {
		struct addr4_lpm_trie key;

		key.prefix = 32;
		key.addr = ip_key->addr[0] & 0xffffffff;
		val = bpf_map_lookup_elem(&addr4lpm_map, &key);
	}
	if (!val)
		return 0;

	return val->id;
}

FUNC_INLINE void find_dns_key(struct destination_endpoint_key *key, struct ip_addr ip_key)
{
	//ToDo
}

FUNC_INLINE uint64_t find_key(struct destination_endpoint_key *key, struct msg_ip_tuple *tuple)
{
	struct destination_endpoint_value *dest;
	struct destination_endpoint_value *destvalue;
	int exists = 0, zero = 0;
	struct tree_id self;

	if (!key->source)
		return 0;

	if (!tuple)
		return 0;

	destvalue = bpf_map_lookup_elem(&destination_endpoint_map, key);
	if (destvalue && destvalue->deny && (destvalue->deny & TNP_POLICY_REFRESH) == 0)
		return destvalue->deny;
	exists = !!destvalue;

	if (!destvalue) {
		destvalue = bpf_map_lookup_elem(&tg_h_ps_dstval, &zero);
		if (!destvalue)
			return 0;

		destvalue->tx_quota = 0;
		destvalue->tx_limit = 0;
		destvalue->tx_drops = 0;
		destvalue->allow_default = 0;
		destvalue->deny_default = 0;
		destvalue->deny = 0;
		destvalue->tx_bytes = 0;
		destvalue->rx_bytes = 0;
		destvalue->policy = 0;
		destvalue->rule = 0;
		destvalue->ipv6 = tuple->ipv6;
		destvalue->ktime_create = bpf_ktime_get_boot_ns();
		destvalue->addr_create[0] = tuple->daddr[0];
		destvalue->addr_create[1] = tuple->daddr[1];
		destvalue->port = tuple->dport;
		destvalue->protocol = tuple->proto;
	}

	/* These do not check TNP_POLICY_REFRESH because we only cache keys for
	 * exact matches. Here we have wildcard lookups.
	 */

	/* Try same port but wildcard protocol (protocol=0 means "any"). */
	key->protocol = 0;
	dest = bpf_map_lookup_elem(&destination_endpoint_map, key);
	if (dest && dest->deny) {
		destvalue->policy = dest->policy;
		destvalue->rule = dest->rule;
		destvalue->deny |= (dest->deny | TNP_POLICY_CACHED);
		key->protocol = tuple->proto;
		bpf_map_update_elem(&destination_endpoint_map, key, destvalue, 0);
		return dest->deny;
	}
	key->protocol = tuple->proto; // restore

	/* Try wildcard port (and protocol). */
	key->port = 0;
	key->protocol = 0;
	dest = bpf_map_lookup_elem(&destination_endpoint_map, key);
	if (dest && dest->deny) {
		destvalue->policy = dest->policy;
		destvalue->rule = dest->rule;
		destvalue->deny |= (dest->deny | TNP_POLICY_CACHED);
		key->port = tuple->dport;
		key->protocol = tuple->proto;
		bpf_map_update_elem(&destination_endpoint_map, key, destvalue, 0);
		return dest->deny;
	}

	self = key->local_id;
	key->local_id.uid = 0;
	key->local_id.cpu = 0;
	/* wildcard local_id, specific port+protocol */
	key->port = tuple->dport;
	key->protocol = tuple->proto;
	dest = bpf_map_lookup_elem(&destination_endpoint_map, key);
	if (dest && dest->deny) {
		destvalue->policy = dest->policy;
		destvalue->rule = dest->rule;
		destvalue->deny |= (dest->deny | TNP_POLICY_CACHED);
		key->local_id = self;
		bpf_map_update_elem(&destination_endpoint_map, key, destvalue, 0);
		return dest->deny;
	}
	/* wildcard local_id with wildcard protocol (specific port) */
	key->protocol = 0;
	dest = bpf_map_lookup_elem(&destination_endpoint_map, key);
	if (dest && dest->deny) {
		destvalue->policy = dest->policy;
		destvalue->rule = dest->rule;
		destvalue->deny |= (dest->deny | TNP_POLICY_CACHED);
		key->local_id = self;
		key->protocol = tuple->proto;
		bpf_map_update_elem(&destination_endpoint_map, key, destvalue, 0);
		return dest->deny;
	}
	/* wildcard local_id, port, and protocol */
	key->port = 0;
	dest = bpf_map_lookup_elem(&destination_endpoint_map, key);
	key->local_id = self; // restore local_id for caller
	key->port = tuple->dport; // restore port for caller
	key->protocol = tuple->proto; // restore protocol for caller
	if (dest && dest->deny) {
		destvalue->policy = dest->policy;
		destvalue->rule = dest->rule;
		destvalue->deny |= (dest->deny | TNP_POLICY_CACHED);
		bpf_map_update_elem(&destination_endpoint_map, key, destvalue, 0);
		return dest->deny;
	}
	if (!exists)
		bpf_map_update_elem(&destination_endpoint_map, key, destvalue, 0);
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
FUNC_INLINE int resolve_key(struct destination_endpoint_key *dnskey,
			    struct destination_endpoint_key *lpmkey,
			    struct destination_endpoint_key *usrkey,
			    struct destination_endpoint_key *destkey,
			    struct msg_ip_tuple *tuple)
{
	uint64_t dnsv, usrv, destv, lpmv, orv;

	dnsv = find_key(dnskey, tuple);
	lpmv = find_key(lpmkey, tuple);
	usrv = find_key(usrkey, tuple);
	destv = find_key(destkey, tuple);

	orv = (dnsv | lpmv | usrv | destv);

	if (orv & TNP_POLICY_DENY) {
		if (dnsv & TNP_POLICY_DENY)
			return dnsv;
		if (lpmv & TNP_POLICY_DENY)
			return lpmv;
		if (usrv & TNP_POLICY_DENY)
			return usrv;
		if (destv & TNP_POLICY_DENY)
			return destv;
	} else if (orv & TNP_POLICY_ALLOW) {
		if (dnsv & TNP_POLICY_ALLOW)
			return dnsv;
		if (lpmv & TNP_POLICY_ALLOW)
			return lpmv;
		if (usrv & TNP_POLICY_ALLOW)
			return usrv;
		if (destv & TNP_POLICY_ALLOW)
			return destv;
	} else {
		struct destination_endpoint_value *dst_value;
		struct destination_endpoint_key *dfltkey, *updatekey;
		int zero = 0;

		dfltkey = bpf_map_lookup_elem(&tg_h_ps_dfltkey, &zero);
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
		if (dnskey->source)
			updatekey = dnskey;
		else if (lpmkey->source)
			updatekey = lpmkey;
		else if (usrkey->source)
			updatekey = usrkey;
		else if (destkey->source)
			updatekey = destkey;
		else
			updatekey = dfltkey;

		/* This also seperates host policy from pod/namespace policy so
		 * that a pod policy will not use default policy from the host.
		 */
		dfltkey->local_nsid = updatekey->local_nsid;
		dfltkey->source = updatekey->source;

		dst_value = bpf_map_lookup_elem(&destination_endpoint_map, dfltkey);
		if (dst_value) {
			struct destination_endpoint_value *destvalue;

			destvalue = bpf_map_lookup_elem(&destination_endpoint_map, updatekey);
			if (destvalue) {
				destvalue->deny = dst_value->deny | TNP_POLICY_FALLTHRU | TNP_POLICY_CACHED;
				destvalue->policy = dst_value->policy;
				destvalue->rule = dst_value->rule;
				return destvalue->deny;
			}

			destvalue = bpf_map_lookup_elem(&tg_h_ps_dstval, &zero);
			if (!destvalue)
				return 0;

			destvalue->ktime_create = bpf_ktime_get_boot_ns();
			destvalue->addr_create[0] = tuple->daddr[0];
			destvalue->addr_create[1] = tuple->daddr[1];
			destvalue->ipv6 = tuple->ipv6;
			destvalue->port = tuple->dport;
			destvalue->protocol = tuple->proto;
			destvalue->deny = dst_value->deny | TNP_POLICY_FALLTHRU | TNP_POLICY_CACHED;
			destvalue->tx_quota = 0;
			destvalue->tx_limit = 0;
			destvalue->tx_bytes = 0;
			destvalue->rx_bytes = 0;
			destvalue->policy = dst_value->policy;
			destvalue->rule = dst_value->rule;

			bpf_map_update_elem(&destination_endpoint_map, updatekey, destvalue, 0);
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

FUNC_INLINE int __process_socketmap_add(struct msg_ip_tuple *tuple, uint64_t pid)
{
	struct destination_endpoint_keys_heap *heap_keys;
	struct destination_endpoint_key *dnskey, *lpmkey, *usrkey, *destkey;
	struct process_tree_config *cfg;
	struct msg_execve_key zero_uid;
	struct tree_id self_uid;
	int zero = 0;
	uint64_t uid;

	struct endpoint_id_value *value;
	struct endpoint_id_key key;
	struct ip_addr ip_key = {};
	uint64_t lpm_id;

	heap_keys = bpf_map_lookup_elem(&tg_h_ps_keys, &zero);
	if (!heap_keys)
		return 0;

	dnskey = &heap_keys->dnskey;
	lpmkey = &heap_keys->lpmkey;
	usrkey = &heap_keys->usrkey;
	destkey = &heap_keys->dstkey;

	if (!dnskey || !lpmkey || !usrkey || !destkey)
		return 0;

	destkey->source = DESTINATION_SOURCE_UNKNOWN;
	usrkey->source = DESTINATION_SOURCE_UNKNOWN;
	lpmkey->source = DESTINATION_SOURCE_UNKNOWN;
	dnskey->source = DESTINATION_SOURCE_UNKNOWN;

	if (!tuple)
		return 0;

	uid = find_myself_by_id(pid);
	self_uid.uid = uid & 0xffffffff;
	self_uid.cpu = uid >> 32;
	/* preserve ignore_args bit from uid (stored in high bit of cpu) */

	/* Appease the verifier on AKS 5.15.180 kernels I've had trouble with
	 * this recently I think they missed some fixes to verifier or something.
	 */
	dnskey->local_id = self_uid;
	lpmkey->local_id = self_uid;
	usrkey->local_id = self_uid;
	destkey->local_id = self_uid;
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
	value = bpf_map_lookup_elem(&tg_endpoint_id_map, &key);
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
	value = bpf_map_lookup_elem(&tg_bpf_endpoint_id_map, &key);
	if (value) {
		destkey->destination_id = value->id;
		destkey->source = DESTINATION_SOURCE_BPF;
	}

	if (usrkey->source > 0 || dnskey->source > 0 || lpmkey->source > 0 || destkey->source > 0)
		goto found_id;

	/* There is no known ID for this IP so lets create one */
	value = bpf_map_lookup_elem(&tg_h_ps_epid, &zero);
	if (!value)
		return 0;
	value->id = __sync_fetch_and_add(&glbl_bpf_endpoint_id, 1);
	destkey->destination_id = value->id;
	destkey->source = DESTINATION_SOURCE_BPF;
	bpf_map_update_elem(&tg_bpf_endpoint_id_map, &key, value, 0);
found_id:
	dnskey->port = tuple->dport;
	lpmkey->port = tuple->dport;
	usrkey->port = tuple->dport;
	destkey->port = tuple->dport;
	dnskey->protocol = tuple->proto;
	lpmkey->protocol = tuple->proto;
	usrkey->protocol = tuple->proto;
	destkey->protocol = tuple->proto;
	dnskey->local_nsid = 0;
	lpmkey->local_nsid = 0;
	usrkey->local_nsid = 0;
	destkey->local_nsid = 0;

	return resolve_key(dnskey, lpmkey, usrkey, destkey, tuple);
}
