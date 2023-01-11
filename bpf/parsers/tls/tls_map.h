#ifndef __TLS_MAP_H
#define __TLS_MAP_H

#include "../bpf_sockops.h"
#include "../../lib/tlsmsg.h"
#include "../../lib/tlsmsg.h"

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 2);
} tls_calls SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, struct msg_tls);
	__uint(max_entries, 32000);
} tls_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __s32);
	__type(value, __s64);
	__uint(max_entries, 1);
} tls_map_stats SEC(".maps");

/* Mark a TLS entry as completed to stop further parsing. */
static inline __attribute__((always_inline)) void
tls_mark_complete(struct msg_tls *tls)
{
	tls->type = 0;
}

static inline __attribute__((always_inline)) void add_tlsmap(__u64 *cookie,
							     struct msg_tls *v)
{
	int err = map_update_elem(&tls_map, cookie, v, 0);
	int zero = 0;
	__s64 *cntr;

	if (!err && (cntr = map_lookup_elem(&tls_map_stats, &zero)))
		*cntr = *cntr + 1;
}

static inline __attribute__((always_inline)) void del_tlsmap(__u64 *cookie)
{
	int err = map_delete_elem(&tls_map, cookie);
	int zero = 0;
	__s64 *cntr;

	if (!err && (cntr = map_lookup_elem(&tls_map_stats, &zero)))
		*cntr = *cntr - 1;
}

struct filter_map {
	char data[128];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct filter_map);
	__uint(max_entries, 1);
} tls_filter_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct filter_map);
	__uint(max_entries, 1);
} http_filter_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct filter_map);
	__uint(max_entries, 1);
} nop_filter_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, u64);
	__uint(max_entries, 1);
} tls_cookie_heap SEC(".maps");

#define PROTO_SKIP  0
#define PROTO_TRACK 1

#define TLS_MAX_PORTS	  10
#define TLS_MAX_SELECTORS 2

#define DO_TLS_PORT_FILTER_ONE(j)                                     \
	p = *(__u32 *)&filter[offset + 4 + 4 + 4 + (4 * j)];          \
	if ((p & 0xffff) == key->dport || (p & 0xffff) == key->sport) \
		goto track;                                           \
	if (++j >= ports)                                             \
		goto skip;

#define DO_TLS_PORT_FILTER                \
	{                                 \
		int j = 0;                \
		DO_TLS_PORT_FILTER_ONE(j) \
		DO_TLS_PORT_FILTER_ONE(j) \
		DO_TLS_PORT_FILTER_ONE(j) \
		DO_TLS_PORT_FILTER_ONE(j) \
		DO_TLS_PORT_FILTER_ONE(j) \
		DO_TLS_PORT_FILTER_ONE(j) \
		DO_TLS_PORT_FILTER_ONE(j) \
		DO_TLS_PORT_FILTER_ONE(j) \
		DO_TLS_PORT_FILTER_ONE(j) \
		DO_TLS_PORT_FILTER_ONE(j) \
	}

static inline __attribute__((always_inline)) int
map_key_filter(u8 *filter, struct sock_key *key)
{
	__u32 selectors, p = 0;
	int i;

	/* Supports upto 10 selectors any more and we simply
	 * mark it as tracked so we fail open. Userspace should
	 * catch this though. And also more than 1 selector
	 * for ports is not useful. An empty filter map indicates
	 * user zero'd filter so we skip the parser. User will
	 * insert -1 to indicate always parse.
	 */
	selectors = (__u32)filter[0];
	if (!selectors)
		goto skip;
	if (selectors < 0)
		goto track;

	/* More than a single selector is unlikely to work unless
	 * we bump up element size.
	 *
	 * TLS selector layout is the following.
	 *
	 *    #OfSelectors         uint32
	 *    OffsetOfEachSelector uint32
	 *    #OfMatchPorts        uint32
	 *    Port1 .... PortN     uint32, uint32, ...
	 */
	for (i = 0; i < 3 && i < (selectors & 0x3); i++) {
		__u32 offset, ports;

		i &= 0xf;
		offset = filter[4 + i * 4];

		offset &= 0x1f;
		ports = filter[offset + 4 + 4]; // max 39
		if (!ports)
			goto track;

		// Zero iteration of hand unrolled loop
		DO_TLS_PORT_FILTER
	}
skip:
	return PROTO_SKIP;
track:
	return p;
}

static inline __attribute__((always_inline)) int
tls_filter(struct sock_key *key)
{
	int zero = 0;
	u8 *filter;

	filter = map_lookup_elem(&tls_filter_map, &zero);
	if (!filter)
		return PROTO_SKIP;

	return map_key_filter(filter, key);
}

static inline __attribute__((always_inline)) bool tls_filter_is_populated()
{
	int zero = 0;
	u8 *filter;

	filter = map_lookup_elem(&tls_filter_map, &zero);
	if (!filter)
		return false;

	return (*(__u32 *)filter) != 0;
}

static inline __attribute__((always_inline)) int
http_filter(struct sock_key *key)
{
	int zero = 0;
	u8 *filter;

	filter = map_lookup_elem(&http_filter_map, &zero);
	if (!filter)
		return PROTO_SKIP;

	return map_key_filter(filter, key);
}

static inline __attribute__((always_inline)) int
nop_filter(struct sock_key *key)
{
	int zero = 0;
	u8 *filter;

	filter = map_lookup_elem(&nop_filter_map, &zero);
	if (!filter)
		return PROTO_SKIP;

	return map_key_filter(filter, key);
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
} tls_parser_stats SEC(".maps");

#define INC_TLS_PARSER_STATS_FUNC(field)                                    \
	static inline __attribute__((always_inline)) void tls_inc_##field() \
	{                                                                   \
		int zero = 0;                                               \
		struct __tls_parser_stats *stats;                           \
		stats = map_lookup_elem(&tls_parser_stats, &zero);          \
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
