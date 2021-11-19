#ifndef __TLS_MAP_H
#define __TLS_MAP_H

#include "../bpf_sockops.h"

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

/* Mark a TLS entry as completed to stop further parsing. */
static inline __attribute__((always_inline))
void tls_mark_complete(struct msg_tls *tls)
{
	tls->type = 0;
}

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

struct bpf_map_def __attribute__((section("maps"), used)) http_filter_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = 128,
	.max_entries = 1,
};

#define PROTO_SKIP  0
#define PROTO_TRACK 1

#define TLS_MAX_PORTS 10
#define TLS_MAX_SELECTORS 2

#define DO_TLS_PORT_FILTER_ONE(j)			     \
	p = *(__u32 *)&filter[offset + 4 + 4 + 4 + (4 * j)]; \
	if (p == key->dport || p == key->sport) goto track;  \
	if (++j >= ports) goto skip;			     \


#define DO_TLS_PORT_FILTER	   \
{				   \
	int j = 0;		   \
	DO_TLS_PORT_FILTER_ONE(j)  \
	DO_TLS_PORT_FILTER_ONE(j)  \
	DO_TLS_PORT_FILTER_ONE(j)  \
	DO_TLS_PORT_FILTER_ONE(j)  \
	DO_TLS_PORT_FILTER_ONE(j)  \
}

static inline __attribute__((always_inline))
int map_key_filter(u8 *filter, struct sock_key *key) {
	__u32 selectors;
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
		__u32 p, offset, ports;

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
	return PROTO_TRACK;
}

static inline __attribute__((always_inline))
int tls_filter(struct sock_key *key) {
	int zero = 0;
	u8 *filter;

	filter = map_lookup_elem(&tls_filter_map, &zero);
	if (!filter)
		return PROTO_SKIP;

	return map_key_filter(filter, key);
}

static inline __attribute__((always_inline))
int http_filter(struct sock_key *key) {
	int zero = 0;
	u8 *filter;

	filter = map_lookup_elem(&http_filter_map, &zero);
	if (!filter)
		return PROTO_SKIP;

	return map_key_filter(filter, key);
}

#endif
