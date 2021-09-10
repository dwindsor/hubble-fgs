#ifndef _HTTP_PARSER_
#define _HTTP_PARSER_

#include "hubble_msg.h"
#include "bpf_events.h"
#include "../bpf_sockops.h"
#include "../parser.h"
#include "http.h"

#ifdef SK_MSG
struct bpf_map_def __attribute__((section("maps"), used)) http1_calls = {
	.type		= BPF_MAP_TYPE_PROG_ARRAY,
	.key_size	= sizeof(__u32),
	.value_size	= sizeof(__u32),
	.max_entries	= 4,
};
#else
struct bpf_map_def __attribute__((section("maps"), used)) http1_calls_skb = {
	.type		= BPF_MAP_TYPE_PROG_ARRAY,
	.key_size	= sizeof(__u32),
	.value_size	= sizeof(__u32),
	.max_entries	= 4,
};
#endif

struct bpf_map_def __attribute__((section("maps"), used)) heap = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(struct msg_http_event),
	.max_entries = 1,
};

#define MAX_HTTP_HDR 512
#define MAX_HTTP_CHARS 32

#ifdef SK_MSG
typedef struct sk_msg_md ctx_md;

static inline __attribute__((always_inline))
int ctx_pull_data(struct sk_msg_md *ctx, __u32 len)
{
	return msg_pull_data(ctx, 0, len, 0);
}
#else
typedef struct __sk_buff ctx_md;

static inline __attribute__((always_inline))
int ctx_pull_data(struct __sk_buff *ctx, __u32 len)
{
	return skb_pull_data(ctx, len);
}
#endif


/* relax_verifier is a dummy helper call to introduce a pruning checkpoint
 * to help relax the verifier to avoid reaching complexity limits.
 */
static inline __attribute__((always_inline)) void relax_verifier(void)
{
       volatile int __maybe_unused id = get_smp_processor_id();
}

static inline __attribute__((always_inline))
char *get_chars(ctx_md *msg, long offset, long cnt)
{
	void *data_end = (void *)(long)msg->data_end;
	void *payload = (void *)(long)msg->data;

	asm volatile ("%[offset] &= 0x1ff;\n": [offset] "+r"(offset)::);
	asm volatile ("%[cnt] &= 0x1f;\n": [cnt] "+r"(cnt)::);
	if (payload + offset + cnt > data_end) {
		ctx_pull_data(msg, offset + cnt);
		return 0;
	}

	return payload + offset;
}

static inline __attribute__((always_inline))
char *get_next_char(ctx_md *msg, struct msg_http *http)
{
	return get_chars(msg, http->offset, 1);
}

static inline __attribute__((always_inline))
char *eat_next_char(ctx_md *msg, struct msg_http *http)
{
	char *c = get_next_char(msg, http);

	http->offset++;
	return c;
}

static inline __attribute__((always_inline))
__u32 __get_method(ctx_md *msg, struct msg_http *http)
{
	char *c = get_chars(msg, http->offset, 3);

	if (!c) {
		return http_method_error;
	}

	switch (c[0]) {
	case 'C':
		http->offset += http_method_connect_off;
		return http_method_connect;
	case 'D':
		http->offset += http_method_delete_off;
		return http_method_delete;
	case 'G':
		http->offset += http_method_get_off;
		return http_method_get;
	case 'H':
		if (c[1] == 'T') {
			http->offset += 0;
			return http_method_response;
		}
		http->offset = http_method_head_off;
		return http_method_head;
	case 'O':
		http->offset += http_method_options_off;
		return http_method_options;
	case 'P':
		if (c[1] == 'O') {
			http->offset += http_method_post_off;
			return http_method_post;
		}
		if (c[1] == 'U') {
			http->offset += http_method_put_off;
			return http_method_put;
		}
		if (c[1] == 'A') {
			http->offset += http_method_patch_off;
			return http_method_patch;
		}
		if (c[1] == 'R' && c[2] == 'I') {
			return http_method_pri;
		}
		return http_method_unknown;
	case 'T':
		http->offset += http_method_trace_off;
		return http_method_trace;
	default:
		return http_method_unknown;
	}
	return http_method_error;
}

static inline __attribute__((always_inline))
__u32 get_method(ctx_md *msg, struct msg_http *http)
{
	http->method = __get_method(msg, http);
	return http->method;
}

#if 0
static inline __attribute__((always_inline))
bool is_space(char c)
{
	return c == ' ';
}
#endif

/* To handle streaming we must copy header fields to a buffer so
 * that when we reach the end of a buffer and need more bytes we
 * can send the first message and keep writing into next_char
 * from here.
 *
 * Implementing the above logic is TBD.
 */
static inline __attribute__((always_inline))
void get_string_scratch(ctx_md *msg, struct msg_http *http, char term)
{
	__u32 *dstsz;
	int i;

	for (i = 0; i < 256 - 4; i++) {
		char *c = eat_next_char(msg, http);

		if (c == 0 || term == c[0] || chr_r == c[0])
			break;
		http->scratch[i+4] = c[0];
	}
	dstsz = (__u32*)http->scratch;
	dstsz[0] = i;
}

static inline __attribute__((always_inline))
bool is_digit(int c)
{
	return (c <= '9' && c >= '0');
}

static inline __attribute__((always_inline))
void get_string(ctx_md *msg, struct msg_http *http,
		char *dst, int ty, int max, char term)
{
	__u32 offset = http->url_offset;
	__u32 *dstsz;
	int i;
	int do_push = (ty == http_request_content_length);

	asm volatile ("%[offset] &= 0x1ff;\n": [offset] "+r"(offset)::);
	for (i = 0; i < max - 8; i++) {
		char *c = eat_next_char(msg, http);

		if (c == 0 || term == c[0])
			break;
		dst[offset+i+8] = c[0];
	}
	dstsz = (__u32*)&dst[offset];
	dstsz[0] = ty;
	dstsz[1] = i;
	http->url_offset += i + 8;

	/* verifier needs a prune point here otherwise we fail on
	 * some kernels.
	 */
	relax_verifier();

	/* Walk the loop again if its content length and convert
	 * into an integer. We can't find a way to convince verifier
	 * to run it above inline with the first loop walk so we
	 * pull it out into its own loop and guard it by contentLength
	 * header type.
	 */
	if (do_push) {
		char *c = (char *)&dstsz[2];
		int value = 0;

		for (i = 0; i < 4; i++) {
			int dig = is_digit(c[i]);

			if (dig) {
				value *= 10;
				value += (int)(c[i]-'0');
			}
		}
		http->consume_bytes = value;
	}
}

static inline __attribute__((always_inline))
void method_get_url(ctx_md *msg, struct msg_http *http)
{
	get_string(msg, http, http->url, http_request_url, 256, chr_sp);
}

static inline __attribute__((always_inline))
void method_get_protocol(ctx_md *msg, struct msg_http *http)
{
	get_string(msg, http, http->url, http_request_protocol, 256, chr_r);
}

static inline __attribute__((always_inline))
int map_header_to_type(ctx_md *msg, struct msg_http *http)
{
	__u32 *sz;

	/* Extra char [5] because we included \n in the 'eat' char */
	sz = (__u32 *)&http->scratch[0];
	if (*sz == 5) {
		char host[4] = HOST;

		if (*(__u32 *)&http->scratch[5] == *(__u32 *)&host[0])
			return http_request_host;
	} else if (*sz == 11) {
		char user[] = USERAGENT;
		__u64 h1 = *(__u64 *)&user[0];
		__u16 h2 = *(__u16 *)&user[8];

		__u64 r1 = *(__u64 *)&http->scratch[5];
		__u16 r2 = *(__u16 *)&http->scratch[13];

		if (r1 == h1 && r2 == h2)
			return http_request_user_agent;
	} else if (*sz == 15) {
		char content_length[] = CONTENT;

		__u64 h1 = *(__u64 *)&content_length[0];
		__u32 h2 = *(__u32 *)&content_length[8];
		__u16 h3 = *(__u16 *)&content_length[12];

		__u64 r1 = *(__u64 *)&http->scratch[5];
		__u32 r2 = *(__u32 *)&http->scratch[13];
		__u16 r3 = *(__u16 *)&http->scratch[17];

		if (r1 == h1 && r2 == h2 && r3 == h3)
			return http_request_content_length;
	/* A header field of 1 indicates we read a \r directly and so this
	 * is a CRLF on a line of its own. If size is zero the parser is lost
	 * but lets try to continue in this case.
	 */
	} else if (*sz <= 1) {
		return http_request_done;
	}
	return http_request_unknown;
}

static inline __attribute__((always_inline))
void get_more_headers(ctx_md *msg)
{
#ifdef SK_MSG
	tail_call(msg, &http1_calls, 2);
#else
	tail_call(msg, &http1_calls_skb, 2);
#endif
}

static inline __attribute__((always_inline))
void find_host_header(ctx_md *msg, struct msg_http *http)
{
	int t;

	// 1
	get_string_scratch(msg, http, chr_colon);
	t = map_header_to_type(msg, http);
	if (t == http_request_done)
		goto out;
	get_string(msg, http, http->url, t, 256, chr_r);

	// 2
	get_string_scratch(msg, http, chr_colon);
	t = map_header_to_type(msg, http);
	if (t == http_request_done)
		goto out;
	get_string(msg, http, http->url, t, 256, chr_r);

	// 3
	get_string_scratch(msg, http, chr_colon);
	t = map_header_to_type(msg, http);
	if (t == http_request_done)
		goto out;
	get_string(msg, http, http->url, t, 256, chr_r);

	// 4
	get_string_scratch(msg, http, chr_colon);
	t = map_header_to_type(msg, http);
	if (t == http_request_done)
		goto out;
	get_string(msg, http, http->url, t, 256, chr_r);

	// 5
	get_string_scratch(msg, http, chr_colon);
	t = map_header_to_type(msg, http);
	if (t == http_request_done)
		goto out;
	get_string(msg, http, http->url, t, 256, chr_r);

	// 6
	get_string_scratch(msg, http, chr_colon);
	t = map_header_to_type(msg, http);
	if (t == http_request_done)
		goto out;
	get_string(msg, http, http->url, t, 256, chr_r);

	// 7
	get_string_scratch(msg, http, chr_colon);
	t = map_header_to_type(msg, http);
	if (t == http_request_done)
		goto out;
	get_string(msg, http, http->url, t, 256, chr_r);

	/* There are still unprocessed headers to lets do a recursive
	 * tail call and eat more headers.
	 */
	get_more_headers(msg);
	return;
out:
	/* Advance past \r\n, we just bump offset because we don't care
	 * about using the char for anything. We may want to add a strict
	 * mode later to ensure it is actually a chr_r. Using relax here
	 * is not ideal, so would be nice to find a better way to satisfy
	 * complexity limits.
	 */
	relax_verifier();
	http->offset++;
}

static inline __attribute__((always_inline))
void method_get_headers(ctx_md *msg, struct msg_http *http)
{
	find_host_header(msg, http);
}

static inline __attribute__((always_inline))
void http_parse_request(ctx_md *msg, struct msg_http *http)
{
	http->url_offset = 0;
	method_get_url(msg, http);
	method_get_protocol(msg, http);
	method_get_headers(msg, http);
}

static inline __attribute__((always_inline))
void response_get_protocol(ctx_md *msg, struct msg_http *http)
{
	get_string(msg, http, http->url, http_response_protocol, 256, chr_sp);
}

static inline __attribute__((always_inline))
void response_get_code(ctx_md *msg, struct msg_http *http)
{
	get_string(msg, http, http->url, http_response_code, 256, chr_sp);
}

static inline __attribute__((always_inline))
void response_get_reason(ctx_md *msg, struct msg_http *http)
{
	get_string(msg, http, http->url, http_response_reason, 256, chr_r);
}

static inline __attribute__((always_inline))
void http_parse_response(ctx_md *msg, struct msg_http *http)
{
	http->url_offset = 0;
	response_get_protocol(msg, http);
	response_get_code(msg, http);
	response_get_reason(msg, http);
	method_get_headers(msg, http);
}

static inline __attribute__((always_inline))
int put_reverse_http_context(struct msg_tls_ipv4 *key, struct msg_http_event *event)
{
	/* Add the receive side entry, so that we'll process the response as HTTP/2 */
	struct msg_tls_ipv4 rkey = {
		.saddr = key->saddr,
		.daddr = key->daddr,
		.dport = key->dport,
		.sport = key->sport,
		.remaining = HTTP_RECV,
	};
	event->request.state = http2_expect_frame;
	return map_update_elem(&http_map, &rkey, event, BPF_NOEXIST);
}

static inline __attribute__((always_inline))
void http_parse(ctx_md *msg, struct msg_http_event *event, struct msg_tls_ipv4 *key)
{
	struct msg_http *http = &event->request;

	if (http->state == http_start) {
		int m = get_method(msg, http);

		switch (m) {
		case http_method_error:
			break;

		case http_method_response:
#ifdef SK_MSG
			tail_call(msg, &http1_calls, 0);
#else
			tail_call(msg, &http1_calls_skb, 0);
#endif
			break;

		case http_method_pri:
			put_reverse_http_context(key, event);
			http->state = http2_expect_preface;
#ifdef SK_MSG
			tail_call(msg, &http1_calls, 3);
#else
			tail_call(msg, &http1_calls_skb, 3);
#endif
			break;

		default:
#ifdef SK_MSG
			tail_call(msg, &http1_calls, 1);
#else
			tail_call(msg, &http1_calls_skb, 1);
#endif
			break;
		}
	}
	http->state = http_done;
}

static inline __attribute__((always_inline))
bool is_expected_request(struct msg_http *http)
{
	return http->state != http_done && http->state != http_error;
}

static inline __attribute__((always_inline))
struct msg_http_event *get_http_context(struct msg_tls_ipv4 *key)
{
	struct msg_http_event *http;

	http = map_lookup_elem(&http_map, key);
	if (!http) {
		struct msg_http_event *__http;
		int zero = 0;

		__http = map_lookup_elem(&http_map_heap, &zero);
		if (!__http)
			goto out;

		map_update_elem(&http_map, key, __http, BPF_NOEXIST);
		http = map_lookup_elem(&http_map, key);
	}
out:
	return http;
}

#ifndef SK_MSG
/* sk_skb_eat_bytes is used to skip the payload of a request/response we are
 * receiving. There are three cases to handle here. First, 'skb->len' is the
 * entire HTTP message (headers and payload) so we can simply consume the
 * skb and reset the parser. The next condition is 'skb->len > skip'. This
 * means we have the start of a new message in the skb. In order to handle
 * this we need to advance the offset to the start of the new header and
 * rekick the parser from this point. And finally the last case is
 * 'skb->len < skip'. In this case we need to consume some number of bytes
 * from the next skb as well.
 */
static inline __attribute__((always_inline))
void sk_skb_eat_bytes(ctx_md *skb,
		      struct msg_http_event *event,
		      struct msg_tls_ipv4 *key,
		      __u32 skip)
{
	struct msg_http *http = &event->request;

	if (skb->len == skip) {
		http->consume_bytes = 0; // do nothing we eat entire skb with SK_PASS
	} else if (skb->len > skip) {
		http->offset = skip;
		http->consume_bytes = 0;    // do nothing we eat entire skb with SK_PASS
		http_parse(skb, event, key); // tail calls into http parser
	} else {
		http->consume_bytes = skip - skb->len;
	}
}
#endif

static inline __attribute__((always_inline))
void http_reset_state(struct msg_http *http)
{
	http->state = http_start;
	http->offset = 0;
	http->url_offset = 0;
	http->consume_bytes = 0;
}

static inline __attribute__((always_inline))
void post_http_event(ctx_md *msg,
		     struct msg_tls_ipv4 *key,
		     struct msg_http_event *http)
{
	struct socketmap_value *process;
	__u32 skip = 0;
	size_t size;
	__u32 *dst;

	process = lookup_socketmap(key);
	if (process) {
		http->execve.pid = process->key.pid;
		http->execve.pad[0] = 0;
		http->execve.pad[1] = 0;
		http->execve.pad[2] = 0;
		http->execve.pad[3] = 0;
		http->execve.ktime = process->key.ktime;
	}

	/* Bounce counters this is a request or response */
	if (http->request.method == http_method_response)
		http->request.recv_cntr++;
	else
		http->request.send_cntr++;

	/* Terminate the payload */
	dst = (__u32*)&http->request.url[http->request.url_offset & 0x1ff];
	dst[0] = 0;
	dst[1] = 0;

	http->common.ktime = ktime_get_ns();
	http->common.op = MSG_OP_HTTP;
	http->common.size = sizeof(struct msg_http_event);
	http->tuple = *key;
	/* NOTE(JM): This workarounds a weird llc bug related to struct packing.
	 * Without this assignment "llc" takes 90s or more instead of <10s
	 */
	http->tuple.remaining = key->remaining;

	size = sizeof(struct __msg_http_event);
	perf_event_output(msg, &tcpmon_map, BPF_F_CURRENT_CPU, http, size);
	skip = http->request.consume_bytes + http->request.offset;
	http_reset_state(&http->request);
#ifdef SK_MSG
	msg_apply_bytes(msg, skip);
#else
	sk_skb_eat_bytes(msg, http, key, skip);
#endif
}

static inline __attribute__((always_inline))
int http_do_parser(ctx_md *msg, struct msg_tls_ipv4 *tuple)
{
	struct msg_http_event *http;

	http = get_http_context(tuple);
	if (unlikely(!http))
		return SK_PASS;

	if (!is_expected_request(&http->request))
		return SK_PASS;

	if (unlikely(http->request.state >= http2_expect_preface)) {
#ifdef SK_MSG
		tail_call(msg, &http1_calls, 3);
#else
		tail_call(msg, &http1_calls_skb, 3);
#endif
		return SK_PASS;
	}

#ifndef SK_MSG
	if (http->request.consume_bytes) {
		sk_skb_eat_bytes(msg, http, tuple, http->request.consume_bytes);
		return SK_PASS;
	}
#endif
	http_parse(msg, http, tuple);
	if (http->request.state == http_done)
		post_http_event(msg, tuple, http);
	return SK_PASS;
}

#endif // _HTTP_PARSER_
