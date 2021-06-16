#include "tls_map.h"
#include "parser.h"

static inline __attribute__((always_inline))
int bpf_sk_msg_tls(struct sk_msg_md *skmsg)
{
	struct msg_tls_ipv4 tuple = {0};
	struct msg_tls clienthello = {0};
	void *payload = skmsg->data;

	skb_tls_key(skmsg, &tuple);

	clienthello.type = 0;
	bpf_parse_tls(skmsg, payload, 0, &clienthello);
	if (is_expected_tls_client_hello(&clienthello))
		add_tlsmap(&tuple, &clienthello);

	return SK_PASS;
}
