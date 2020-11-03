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

#define ENEXTTOOLARGE	1
#define EGETDATA	2
#define ENOBUFFER	3
#define ECOPYERROR	4

#define TLS_HEADER_BYTES 9

/* TBD: JF, extend verifier to understand void functions */
int bpf_skskb_post_cert(struct __sk_buff *skb, int next)
{
	void *data, *data_end = (void *)(long)skb->data_end;
	void *tls_server_hello = (void*)(long)skb->data;
	struct tls_handshake_certificate *cert;
	int *length, copied, zero = 0, errout[2];
	__u32 csize = 0;
	__u8 *buffer;

	next += TLS_HEADER_BYTES; // Account for TLS Server Hello header
	if (next > 1024) {
		errout[1] = ENEXTTOOLARGE;
		goto out;
	}

	asm volatile ("%[next] &= 0x0fff;\n": [next] "+r"(next)::);
	data = (void*)tls_server_hello + next;
	if (data + sizeof(struct tls_handshake_certificate) > data_end) {
		data = get_data(skb, next, sizeof(struct tls_handshake_certificate));
		if (!data) {
			errout[1] = EGETDATA;
			goto out;
		}
		data_end = (void *)(long)skb->data_end;
	}
	compiler_barrier();
	cert = (struct tls_handshake_certificate *)data;
	csize = cert->length;
	csize = bpf_ntohs(csize);
	csize += 4 + 1;

	/* We get away with posting without a header because we have
	 * a flag above indicating the cert is the next event and this
	 * is a non-preemptive hook so we can be certain the user side
	 * will in-fact get this event immediately after above.
	 */
	buffer = map_lookup_elem(&tls_heap, &zero);
	if (!buffer) {
		errout[1] = ENOBUFFER;
		goto out;
	}

	/* It seems compiler and verifier are conspiring to reject my
	 * copy code. So loops generate code that wont prune and exceeds
	 * 1mil insn similarly unrolled loops do as well. So brute force
	 * this and macro it out and put code we want in via asm.
	 */
	copied = large_ctx_copy(skb, next, 0, csize);
	/* We need at least enough bytes to get to certificate length
	 * otherwise user space side will not be able to parse initial
	 * length and will have to bail out anyways. Mind as well send
	 * an error early.
	 */
	if (copied < 15) {
		errout[1] = ECOPYERROR;
		goto out;
	}

	/* total bound clamp because verifier lost it from above :( */
	asm volatile ("%[copied] &= 0x0fff;\n": [copied] "+r"(copied)::);
	length = (int *)buffer;
	*length = copied;
	perf_event_output(skb, &tcpmon_map, BPF_F_CURRENT_CPU, buffer, copied);
	return 0;
out:
	/* userspace wants to see an event so we generate an error event */
	errout[0] = 0;
	perf_event_output(skb, &tcpmon_map, BPF_F_CURRENT_CPU, errout, sizeof(errout));
	return 0;
}

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
		int zero = 0;
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

		if (!(post->serverhello.flags & TLS_VERSION))
			bpf_skskb_post_cert(skb, next);
	}
	return SK_PASS;
}
