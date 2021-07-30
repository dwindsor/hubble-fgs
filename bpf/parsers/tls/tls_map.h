#ifndef __TLS_MAP_H
#define __TLS_MAP_H

struct bpf_map_def __attribute__((section("maps"), used)) tls_calls = {
	.type		= BPF_MAP_TYPE_PROG_ARRAY,
	.key_size	= sizeof(__u32),
	.value_size	= sizeof(__u32),
	.max_entries	= 2,
};

struct bpf_map_def __attribute__((section("maps"), used)) tls_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct msg_tls_ipv4),
	.value_size = sizeof(struct msg_tls),
	.max_entries = 32000,
};

static inline __attribute__((always_inline))
void add_tlsmap(struct msg_tls_ipv4 *tuple, struct msg_tls *v)
{
	int err = map_update_elem(&tls_map, tuple, v, 0);
	int zero = 0;
	__s64 *cntr;

	if (!err && (cntr = map_lookup_elem(&tls_map_stats, &zero)))
		*cntr = *cntr + 1;
}

static inline __attribute__((always_inline))
void del_tlsmap(struct msg_tls_ipv4 *tuple)
{
	int err = map_delete_elem(&tls_map, tuple);
	int zero = 0;
	__s64 *cntr;

	if (!err && (cntr = map_lookup_elem(&tls_map_stats, &zero)))
		*cntr = *cntr - 1;
}

struct bpf_map_def __attribute__((section("maps"), used)) tls_filter_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = 128,
	.max_entries = 1,
};
#endif
