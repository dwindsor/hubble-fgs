#include "hubble_msg.h"
#include "bpf_events.h"
#include "../bpf_sockops.h"
#include "parser.h"
#include "tls_map.h"

struct bpf_map_def __attribute__((section("maps"), used)) heap = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(struct msg_tls_event),
	.max_entries = 1,
};

int bpf_skskb_verdict_tls(struct __sk_buff *skb)
{
	struct msg_tls_ipv4 key = {0};
	struct msg_tls *event;

	sk_skb_tls_key(skb, &key);

	event = map_lookup_elem(&tls_map, &key);
	if (!event)
		return SK_PASS;

	if (is_expected_tls_client_hello(event)) {
		struct msg_execve_key *execve;
		struct msg_tls_event *post;
		void *payload = (void*)(long)skb->data;
		const int zero = 0;
		int err;

		post = map_lookup_elem(&heap, &zero);
		if (!post)
			return SK_PASS;

		post->clienthello = *event;
		memset(&post->serverhello, 0, sizeof(post->serverhello));

		err = bpf_parse_tls(skb, payload, 0, &post->serverhello);
		if (err < 0)
			return SK_PASS;

		if (!is_expected_tls_server_hello(&post->serverhello))
			return SK_PASS;

		post->tuple = key;
		post->common.op = MSG_OP_TLS;
		post->common.size = sizeof(struct msg_tls_event);
		post->common.ktime = ktime_get_ns();

		execve  = lookup_socketmap(&key);
		if (execve)
			post->execve = *execve;

		perf_event_output(skb, &tcpmon_map, BPF_F_CURRENT_CPU, post,
				  sizeof(struct msg_tls_event));
		event->type = 0;
		post->serverhello.alert_level = 0;
		post->clienthello.alert_level = 0;
	}
	return SK_PASS;
}
