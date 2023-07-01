#ifndef __TLS_MAP_H
#define __TLS_MAP_H

#include "../bpf_sockops.h"
#include "../../lib/tlsmsg.h"
#include "../../lib/tlsmsg.h"
#include "bpf_tracing.h"

#define TLS_MAX_PORTS 512

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 2);
} tg_tls_calls SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, struct msg_tls);
	__uint(max_entries, 32000);
} tg_tls_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __s32);
	__type(value, __s64);
	__uint(max_entries, 1);
} tg_tls_map_stats SEC(".maps");

/* Mark a TLS entry as completed to stop further parsing. */
static inline __attribute__((always_inline)) void
tls_mark_complete(struct msg_tls *tls)
{
	tls->type = 0;
}

static inline __attribute__((always_inline)) void add_tlsmap(__u64 *cookie,
							     struct msg_tls *v)
{
	int err = map_update_elem(&tg_tls_map, cookie, v, 0);
	int zero = 0;
	__s64 *cntr;

	if (!err && (cntr = map_lookup_elem(&tg_tls_map_stats, &zero)))
		*cntr = *cntr + 1;
}

static inline __attribute__((always_inline)) void del_tlsmap(__u64 *cookie)
{
	int err = map_delete_elem(&tg_tls_map, cookie);
	int zero = 0;
	__s64 *cntr;

	if (!err && (cntr = map_lookup_elem(&tg_tls_map_stats, &zero)))
		*cntr = *cntr - 1;
}

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u8);
	__uint(max_entries, TLS_MAX_PORTS);
} tg_tls_filter_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u8);
	__uint(max_entries, TLS_MAX_PORTS);
} tg_http_filter_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u8);
	__uint(max_entries, TLS_MAX_PORTS);
} tg_nop_filter_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, u64);
	__uint(max_entries, 1);
} tg_tls_cookie_heap SEC(".maps");

#define PROTO_SKIP  0
#define PROTO_TRACK 1

static inline __attribute__((always_inline)) int
map_key_filter(void *filter_map, struct sock_key *key)
{
	__u32 sport = key->sport;
	__u32 dport = key->dport;

	if (map_lookup_elem(filter_map, &sport)) {
		return PROTO_TRACK;
	}

	if (map_lookup_elem(filter_map, &dport)) {
		return PROTO_TRACK;
	}

	return PROTO_SKIP;
}

static inline __attribute__((always_inline)) int
tls_filter(struct sock_key *key)
{
	return map_key_filter(&tg_tls_filter_map, key);
}

static inline __attribute__((always_inline)) int
http_filter(struct sock_key *key)
{
	return map_key_filter(&tg_http_filter_map, key);
}

static inline __attribute__((always_inline)) int
nop_filter(struct sock_key *key)
{
	return map_key_filter(&tg_nop_filter_map, key);
}

struct __tls_parser_stats {
	__u64 cnt_egress_out_of_data;
	__u64 cnt_egress_parse_error;
	__u64 cnt_egress_ok;

	__u64 cnt_ingress_out_of_data;
	__u64 cnt_ingress_parse_error;
	__u64 cnt_ingress_ok;

	__u64 cnt_bottle_fill_failed;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __s32);
	__type(value, struct __tls_parser_stats);
	__uint(max_entries, 1);
} tg_tls_parser_stats SEC(".maps");

#define INC_TLS_PARSER_STATS_FUNC(field)                                    \
	static inline __attribute__((always_inline)) void tls_inc_##field() \
	{                                                                   \
		int zero = 0;                                               \
		struct __tls_parser_stats *stats;                           \
		stats = map_lookup_elem(&tg_tls_parser_stats, &zero);       \
		if (stats)                                                  \
			stats->cnt_##field++;                               \
	}

INC_TLS_PARSER_STATS_FUNC(egress_out_of_data); /* tls_inc_egress_out_of_data() */
INC_TLS_PARSER_STATS_FUNC(egress_parse_error);
INC_TLS_PARSER_STATS_FUNC(egress_ok);

INC_TLS_PARSER_STATS_FUNC(ingress_out_of_data);
INC_TLS_PARSER_STATS_FUNC(ingress_parse_error);
INC_TLS_PARSER_STATS_FUNC(ingress_ok);

INC_TLS_PARSER_STATS_FUNC(bottle_fill_failed);

#endif
