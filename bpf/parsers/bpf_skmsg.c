#include "vmlinux.h"
#include "api.h"

#ifndef bpf_map_def
struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};
#endif

#define SK_MSG
#define TLS_PORT 443

#include "hubble_msg.h"
#include "bpf_events.h"
#include "bpf_sockops.h"
#include "tls/tls_map.h"
#include "tls/parser.h"

char _license[] __attribute__((section(("license")), used)) = "GPL";

__attribute__((section(("sk_msg/fgs")), used))
int bpf_sk_msg_fgs(struct sk_msg_md *skmsg)
{
	struct msg_tls_ipv4 tuple = {0};
	struct msg_tls clienthello = {0};

	/* Clear the cork bytes so next message won't be subject to corking,
         * unless needed by msg_bottle_get_data. */
	msg_cork_bytes(skmsg, 0);

	skb_tls_key(skmsg, &tuple);

	if (map_lookup_elem(&tls_map, &tuple))
		/* Already parsed, or parsing failed and should ignore. */
		return SK_PASS;

	int err = bpf_parse_tls(skmsg, &clienthello);
	if (err != TLS_PARSE_OUT_OF_DATA) {
		/* Success or parse failure, regardless add to the TLS map
                 * to either stop parsing or switch to parsing the server hello. */
		add_tlsmap(&tuple, &clienthello);
	}

	return SK_PASS;
}
