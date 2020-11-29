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

#define SK_SKB
int bpf_skskb_verdict_tls(struct __sk_buff *skb)
{
	struct msg_tls_ipv4 key = {0};
	struct msg_execve_key *execve;
	struct msg_tls *event;
	int zero = 0;
	__u32 cb0 = 0;

	sk_skb_tls_key(skb, &key);

	event = map_lookup_elem(&tls_map, &key);
	if (!event)
		return SK_PASS;

	if (is_expected_tls_client_hello(event)) {
		struct msg_tls_event *post;
		void *payload = (void*)(long)skb->data;
		int next;

		post = map_lookup_elem(&heap, &zero);
		if (!post)
			return SK_PASS;

		post->clienthello = *event;
		memset(&post->serverhello, 0, sizeof(post->serverhello));

		next = bpf_parse_tls(skb, payload, 0, &post->serverhello);
		if (next < 0)
			return SK_PASS;

		if (!is_expected_tls_server_hello(&post->serverhello))
			return SK_PASS;

		/* If this there is a next pointer and it is TLSv1.2 lets assume
		 * its the cert and push it to user space.
		 */
		if (!(post->serverhello.flags & TLS_VERSION))
			post->serverhello.flags |= TLS_CERT;

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

		if (!(post->serverhello.flags & TLS_VERSION)) {
			event->bytes = bpf_skskb_post_cert(skb, event, next, &cb0);
			if (event->bytes)
				event->type = TLS_TYPE_MORE_DATA;
		}
	} else if (is_expected_tls_data(event)) {
		struct msg_tls_event *post;

		post = map_lookup_elem(&heap, &zero);	
		if (!post)
			return SK_PASS;

		post->tuple = key;
		post->common.op = MSG_OP_TLS;
		post->common.size = sizeof(struct msg_tls_event);
		post->common.ktime = ktime_get_ns();

		execve = lookup_socketmap(&key);
		if (execve)
			post->execve = *execve;
		post->serverhello.flags |= TLS_CERT;
		perf_event_output(skb, &tcpmon_map, BPF_F_CURRENT_CPU, post, sizeof(struct msg_tls_event));
		event->bytes = bpf_skskb_post_more_cert(skb, event, 0, event->bytes);
		return SK_PASS;
	}

	return SK_PASS;
}
