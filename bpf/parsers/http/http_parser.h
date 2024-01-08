// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef _HTTP_PARSER_
#define _HTTP_PARSER_

#include "vmlinux.h"
#include "iso_msg_types.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "../bpf_sockops.h"
#include "../parser.h"
#include "http.h"
#include "bpf_helpers.h"
#include "../../networking/cookie.h"

#ifdef SK_MSG
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 4);
} http1_calls SEC(".maps");
#else
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 4);
} http1_calls_skb SEC(".maps");
#endif

#define MAX_HTTP_HDR   512
#define MAX_HTTP_CHARS 32

#ifdef SK_MSG
typedef struct sk_msg_md ctx_md;

static inline __attribute__((always_inline)) int
ctx_pull_data(struct sk_msg_md *ctx, __u32 len)
{
	return msg_pull_data(ctx, 0, len, 0);
}
#else
typedef struct __sk_buff ctx_md;

static inline __attribute__((always_inline)) int
ctx_pull_data(struct __sk_buff *ctx, __u32 len)
{
	return skb_pull_data(ctx, len);
}
#endif

static inline __attribute__((always_inline)) struct msg_http_event *
get_http_context(ctx_md *msg)
{
	struct msg_http_event *http;
	u64 cookie = (u64)msg->sk;

	http = map_lookup_elem(&tg_http_map, &cookie);
	if (!http) {
		struct msg_http_event *__http;
		int zero = 0;

		__http = map_lookup_elem(&tg_http_map_heap, &zero);
		if (!__http)
			goto out;

		map_update_elem(&tg_http_map, &cookie, __http, BPF_NOEXIST);
		http = map_lookup_elem(&tg_http_map, &cookie);
	}
out:
	return http;
}

static inline __attribute__((always_inline)) void
post_http_event_cont(ctx_md *msg, struct msg_http_event *http);

__attribute__((noinline)) int get_string_scratch(ctx_md *msg, char term);

static inline __attribute__((always_inline)) char *
get_chars(ctx_md *msg, long offset, long cnt)
{
	void *data_end = (void *)(long)msg->data_end;
	void *payload = (void *)(long)msg->data;

	asm volatile("%[offset] &= 0x7fff;\n"
		     : [offset] "+r"(offset)::);
	asm volatile("%[cnt] &= 0x1f;\n"
		     : [cnt] "+r"(cnt)::);
	if (payload + offset + cnt > data_end) {
		ctx_pull_data(msg, offset + cnt);

		data_end = (void *)(long)msg->data_end;
		payload = (void *)(long)msg->data;

		asm volatile("%[offset] &= 0x3ff;\n"
			     : [offset] "+r"(offset)::);
		asm volatile("%[cnt] &= 0x1f;\n"
			     : [cnt] "+r"(cnt)::);
		if (payload + offset + cnt > data_end)
			return 0;
		return payload + offset;
	}

	return payload + offset;
}

static inline __attribute__((always_inline)) char *
get_next_char(ctx_md *msg, struct msg_http *http)
{
	return get_chars(msg, http->offset, 1);
}

static inline __attribute__((always_inline)) char *
eat_next_char(ctx_md *msg, struct msg_http *http)
{
	char *c = get_next_char(msg, http);

	http->offset++;
	return c;
}

static inline __attribute__((always_inline)) int
strncmp_truncated(const char *s1, __u32 s1_sz, const char *s2, __u32 s2_sz)
{
	int diff;
	int i;

	for (i = 0; i < s1_sz && i < s2_sz; i++) {
		diff = s1[i] - s2[i];
		if (diff != 0) {
			return diff;
		}
	}
	return 0;
}

static inline __attribute__((always_inline)) __u32
__get_method(ctx_md *msg, struct msg_http *http)
{
	int sz;
	__u32 old_offset = http->offset;

	sz = get_string_scratch(msg, chr_sp);

	if (http->state == http_more_headers_needed) {
		return http_method_split;
	}

	http->scratch[0] = (u32)0;

	if (!strncmp_truncated(http->scratch + 4, sz, "connect", 7)) {
		return http_method_connect;
	}

	if (!strncmp_truncated(http->scratch + 4, sz, "delete", 6)) {
		return http_method_delete;
	}

	if (!strncmp_truncated(http->scratch + 4, sz, "get", 3)) {
		return http_method_get;
	}

	if (!strncmp_truncated(http->scratch + 4, sz, "head", 4)) {
		return http_method_head;
	}

	if (!strncmp_truncated(http->scratch + 4, sz, "options", 7)) {
		return http_method_options;
	}

	if (!strncmp_truncated(http->scratch + 4, sz, "post", 4)) {
		return http_method_post;
	}

	if (!strncmp_truncated(http->scratch + 4, sz, "put", 3)) {
		return http_method_put;
	}

	if (!strncmp_truncated(http->scratch + 4, sz, "patch", 5)) {
		return http_method_patch;
	}

	if (!strncmp_truncated(http->scratch + 4, sz, "trace", 5)) {
		return http_method_trace;
	}

	if (!strncmp_truncated(http->scratch + 4, sz, "pri", 3)) {
		// We need to walk the parser back here since http2 parser wants to do string
		// matching on PRI for the http2 preface.
		http->offset = old_offset;
		return http_method_pri;
	}

	if (!strncmp_truncated(http->scratch + 4, sz, "http", 4)) {
		// We need to walk the parser back here since we also want to parse this out as
		// the response protocol.
		http->offset = old_offset;
		return http_method_response;
	}

	return http_method_unknown;
}

static inline __attribute__((always_inline)) __u32
get_method(ctx_md *msg, struct msg_http *http)
{
	http->method = __get_method(msg, http);
	return http->method;
}

static inline __attribute__((always_inline)) bool is_space(char c)
{
	return c == ' ';
}

/* To handle streaming we must copy header fields to a buffer so
 * that when we reach the end of a buffer and need more bytes we
 * can send the first message and keep writing into next_char
 * from here.
 *
 * Implementing the above logic is TBD.
 */
__attribute__((noinline)) int get_string_scratch(ctx_md *msg, char term)
{
	struct msg_http_event *event;
	struct msg_http *http;

	event = get_http_context(msg);
	if (unlikely(!event))
		return -1;
	http = &event->request;

	__u32 *dstsz = (__u32 *)http->scratch;
	__u64 off = (int)dstsz[0];
	__u64 i;
	char v, *c = 0;

	for (i = 0; i < 256 - 4; i++) {
		c = eat_next_char(msg, http);
		if (!c)
			break;
		v = *c;
		if (term == v || chr_r == v)
			break;
		if (v >= 'A' & v <= 'Z')
			v += 32;
		asm volatile("%[off] &= 0xff;\n"
			     : [off] "+r"(off)::);
		http->scratch[off + i + 4] = v;
	}
	dstsz[0] = i + off;
	/* Buffer does not contain terminating char so we build
	 * a continuation state
	 */
	if (!c) {
		http->offset = 0;
		http->state = http_more_headers_needed;
	}
	DEBUG("read(%d): %s", *dstsz, http->scratch + 4);
	return *dstsz;
}

static inline __attribute__((always_inline)) bool is_digit(int c)
{
	return (c <= '9' && c >= '0');
}

static inline __attribute__((always_inline)) void
get_string(ctx_md *msg, struct msg_http_event *event,
	   struct msg_http *http, char *dst, int ty, __u64 max, char term)
{
	int do_push = (ty == http_request_content_length);
	__u32 offset = http->url_offset;
	__u32 *dstsz;
	char *c;
	__u64 i;

	if (offset + max > 0x3ff) {
		http->flags = HTTP_MORE_HEADERS_NEEDED;
		http->state = http_more_headers_needed;
		post_http_event_cont(msg, event);
		return;
	}

	offset += http->url_continue;
	/* Playing games with the verifier here, in order to get a good prune
	 * point we introduce a nop. TBD sort out the details around this and
	 * see if we can fix verifier/clang to do the right thing without
	 * introducing cryptic and ugly asm.
	 */
	asm volatile("%[i] += 0;\n"
		     : [i] "+r"(i)::);
	asm volatile("%[offset] &= 0x3ff;\n"
		     : [offset] "+r"(offset)::);

	for (i = 0; i < max - 8; i++) {
		c = eat_next_char(msg, http);

		if (c == 0 || term == c[0])
			break;
		dst[offset + i + 8] = c[0];
	}

	/* If we consumed the buffer and never found the '\r\n' pattern to
	 * terminate the header value, mark the state as more data needed
	 * and wait for next buffer.
	 */
	if (!c) {
		http->url_continue += i;
		http->offset = 0;
		http->state = http_more_headers_value_needed;
		/* nop necessary to convince clang not to spill this register
		 * which then causes the verifier to lose the bounds. Note
		 * a relax_verifier() is insufficient to convince verifier
		 * here.
		 */
		asm volatile("%[cont] += 0;\n"
			     : [cont] "+r"(http->url_continue)::);
		return;
	}

	/* Verifier lost offset bound on older kernels <5.10 presumably because
	 * it was pushed into stack and we only recently added bounds tracking
	 * through stack. So duplicate the offset bound here.
	 */
	offset = http->url_offset;
	asm volatile("%[offset] &= 0x3ff;\n"
		     : [offset] "+r"(offset)::);
	dstsz = (__u32 *)&dst[offset];
	dstsz[0] = ty;
	dstsz[1] = i + http->url_continue;

	http->state = http_get_headers;
	http->url_offset = offset + http->url_continue + i + 8;
	http->url_continue = 0;

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

		for (i = 0; i < 10; i++) {
			int dig = is_digit(c[i]);

			if (dig) {
				value *= 10;
				value += (int)(c[i] - '0');
			} else if (!is_space(c[i])) {
				break;
			}
		}
		http->consume_bytes = value;
	}
}

__attribute__((noinline)) int method_get_url(ctx_md *msg)
{
	struct msg_http_event *event;
	struct msg_http *http;

	event = get_http_context(msg);
	if (unlikely(!event))
		return SK_PASS;

	http = &event->request;
	get_string(msg, event, http, http->url, http_request_url, 256, chr_sp);
	return 0;
}

__attribute__((noinline)) int method_get_protocol(ctx_md *msg)
{
	struct msg_http_event *event;
	struct msg_http *http;

	event = get_http_context(msg);
	if (unlikely(!event))
		return SK_PASS;

	http = &event->request;

	get_string(msg, event, http, http->url, http_request_protocol, 256,
		   chr_r);
	return 0;
}

static inline __attribute__((always_inline)) int
map_header_to_type(ctx_md *msg, struct msg_http *http)
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
	} else if (*sz == 18) {
		char transfer[] = TRANSFER;

		__u64 h1 = *(__u64 *)&transfer[0];
		__u64 h2 = *(__u64 *)&transfer[8];
		__u8 h3 = *(__u8 *)&transfer[16];

		__u64 r1 = *(__u64 *)&http->scratch[5];
		__u64 r2 = *(__u64 *)&http->scratch[13];
		__u8 r3 = *(__u8 *)&http->scratch[21];

		if (r1 == h1 && r2 == h2 && r3 == h3)
			return http_request_transfer_encoding;

		/* A header field of 1 indicates we read a \r directly and so this
	 * is a CRLF on a line of its own. If size is zero the parser is lost
	 * but lets try to continue in this case.
	 */
	} else if (*sz <= 1) {
		return http_request_done;
	}
	return http_request_unknown;
}

static inline __attribute__((always_inline)) void get_more_headers(ctx_md *msg)
{
#ifdef SK_MSG
	tail_call(msg, &http1_calls, 2);
#else
	tail_call(msg, &http1_calls_skb, 2);
#endif
}

__attribute__((noinline)) int continue_header_string(ctx_md *msg)
{
	struct msg_http_event *event;
	struct msg_http *http;
	int t;

	event = get_http_context(msg);
	if (unlikely(!event))
		return 0;
	http = &event->request;

	t = map_header_to_type(msg, http);
	get_string(msg, event, http, http->url, t, 256, chr_r);
	if (http->state == http_more_headers_value_needed)
		return 0;
	http->scratch[0] = (u32)0;
	get_more_headers(msg);
	return 0;
}

#define HTTP_REQUEST_MORE 0
#define HTTP_REQUEST_DONE 1
#define HTTP_REQUEST_CONT 2

__attribute__((noinline)) int get_string_r(ctx_md *msg)
{
	struct msg_http_event *event;
	struct msg_http *http;
	int t;

	event = get_http_context(msg);
	if (unlikely(!event))
		return -1;
	http = &event->request;

	if (http->state == http_more_headers_needed)
		return HTTP_REQUEST_MORE;

	t = map_header_to_type(msg, http);
	if (t == http_request_done)
		return HTTP_REQUEST_DONE;

	get_string(msg, event, http, http->url, t, 256, chr_r);
	return HTTP_REQUEST_CONT;
}

static inline __attribute__((always_inline)) void
find_host_header(ctx_md *msg, struct msg_http_event *event, struct msg_http *http)
{
	int err;

	// 1
	get_string_scratch(msg, chr_colon);
	err = get_string_r(msg);
	if (err <= 0)
		return;
	if (err == HTTP_REQUEST_DONE)
		goto out;

	http->scratch[0] = (u32)0;

	// 2
	get_string_scratch(msg, chr_colon);
	err = get_string_r(msg);
	if (err <= 0)
		return;
	if (err == HTTP_REQUEST_DONE)
		goto out;

	http->scratch[0] = (u32)0;

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
	http->state = http_done;
	relax_verifier();
	http->offset++;
}

__attribute__((noinline)) int method_get_headers(ctx_md *msg)
{
	struct msg_http_event *event;
	struct msg_http *http;

	event = get_http_context(msg);
	if (unlikely(!event))
		return -1;

	http = &event->request;
	http->state = http_get_headers;
	find_host_header(msg, event, http);
	return 0;
}

__attribute__((noinline)) int http_parse_request(ctx_md *msg)
{
	struct msg_http_event *http;

	http = get_http_context(msg);
	if (unlikely(!http))
		return 0;

	http->request.url_offset = 0;

	method_get_url(msg);
	method_get_protocol(msg);
	method_get_headers(msg);

	if (http->request.state == http_more_headers_needed ||
	    http->request.state == http_more_headers_value_needed)
		return 0;

	http->request.state = http_done;
	return 1;
}

__attribute__((noinline)) int response_get_protocol(ctx_md *msg)
{
	struct msg_http_event *event;
	struct msg_http *http;

	event = get_http_context(msg);
	if (unlikely(!event))
		return -1;
	http = &event->request;

	get_string(msg, event, http, http->url, http_response_protocol,
		   256, chr_sp);
	return 0;
}

__attribute__((noinline)) int response_get_code(ctx_md *msg)
{
	struct msg_http_event *event;
	struct msg_http *http;

	event = get_http_context(msg);
	if (unlikely(!event))
		return -1;
	http = &event->request;

	get_string(msg, event, http, http->url, http_response_code, 256, chr_sp);
	return 0;
}

__attribute__((noinline)) int response_get_reason(ctx_md *msg)
{
	struct msg_http_event *event;
	struct msg_http *http;

	event = get_http_context(msg);
	if (unlikely(!event))
		return -1;
	http = &event->request;

	get_string(msg, event, http, http->url, http_response_reason, 256,
		   chr_r);
	return 0;
}

__attribute__((noinline)) int http_parse_response(ctx_md *msg)
{
	struct msg_http_event *event;
	struct msg_http *http;

	event = get_http_context(msg);
	if (unlikely(!event))
		return 0;
	http = &event->request;

	http->url_offset = 0;
	response_get_protocol(msg);
	response_get_code(msg);
	response_get_reason(msg);

	method_get_headers(msg);

	if (event->request.state == http_more_headers_needed ||
	    event->request.state == http_more_headers_value_needed)
		return 0;

	event->request.state = http_done;
	return 1;
}

/* HTTP Parser is organized into a series of tail calls that splits this into
 * http1_request, http1_reply, http2, and header_parsing. Entry point from
 * primary BPF verdict and sk_msg hooks sk_msg/fgs and sk_skb/fgs.
 */
static inline __attribute__((always_inline)) void
http_parse(ctx_md *msg, struct msg_http_event *event)
{
	struct msg_http *http = &event->request;

	if (http->state == http_start || http->state == http_request_state_method_split) {
		int m = get_method(msg, http);

		switch (m) {
		case http_method_split:
			http->state = http_request_state_method_split;
			goto out;

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
			http->state = http2_expect_preface;
#ifdef SK_MSG
			tail_call(msg, &http1_calls, 3);
#else
			tail_call(msg, &http1_calls_skb, 3);
#endif
			break;

		case http_method_unknown:
			break;

		default:
#ifdef SK_MSG
			tail_call(msg, &http1_calls, 1);
#else
			tail_call(msg, &http1_calls_skb, 1);
#endif
			break;
		}
	} else if (http->state >= http2_expect_preface) {
#ifdef SK_MSG
		tail_call(msg, &http1_calls, 3);
#else
		tail_call(msg, &http1_calls_skb, 3);
#endif
	} else if (http->state == http_more_headers_needed) {
#ifdef SK_MSG
		tail_call(msg, &http1_calls, 2);
#else
		tail_call(msg, &http1_calls_skb, 2);
#endif
		return;
	} else if (http->state == http_more_headers_value_needed) {
		/* Wrapper around tail call to /2 */
		continue_header_string(msg);
		return;
	}

	// Dead code everything above tail calls from main prog
	http->state = http_done;
out:
	return;
}

static inline __attribute__((always_inline)) bool
is_expected_request(struct msg_http *http)
{
	return http->state != http_done && http->state != http_error;
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
static inline __attribute__((always_inline)) void
sk_skb_eat_bytes(ctx_md *skb, struct msg_http_event *event, __u32 skip)
{
	struct msg_http *http = &event->request;

	if (skb->len == skip) {
		http->consume_bytes =
			0; // do nothing we eat entire skb with SK_PASS
	} else if (skb->len > skip) {
		http->offset = skip;
		http->consume_bytes =
			0; // do nothing we eat entire skb with SK_PASS
		http_parse(skb, event); // tail calls into http parser
	} else {
		http->consume_bytes = skip - skb->len;
	}
}
#endif

static inline __attribute__((always_inline)) void
http_reset_state(struct msg_http *http)
{
	http->state = http_start;
	http->offset = 0;
	http->url_offset = 0;
	http->url_continue = 0;
	http->consume_bytes = 0;
	http->flags = 0;
	http->scratch[0] = (u32)0;
}

static inline __attribute__((always_inline)) void
post_http_event_cont(ctx_md *msg, struct msg_http_event *http)
{
	struct socketmap_value *process;
	size_t size;
	u64 cookie;

	cookie = (u64)msg->sk;
	process = lookup_socketmap(&cookie);
	if (!process)
		return;

	http->execve.pid = process->key.pid;
	http->execve.pad[0] = 0;
	http->execve.pad[1] = 0;
	http->execve.pad[2] = 0;
	http->execve.pad[3] = 0;
	http->execve.ktime = process->key.ktime;

	if (http->request.method == http_method_response)
		http->request.recv_cntr++;
	else
		http->request.send_cntr++;

	http->common.ktime = ktime_get_ns();
	http->common.op = ISO_MSG_OP_HTTP;
	http->common.size = sizeof(struct __msg_http_event);
	http->tuple = process->tuple;

	size = sizeof(struct __msg_http_event);
	perf_event_output_metric(msg, ISO_MSG_OP_HTTP, &tcpmon_map, BPF_F_CURRENT_CPU, http, size);

	/* This is a special caller when we know more headers are needed */
	if (http->request.method == http_method_response)
		http->request.recv_cntr--;
	else
		http->request.send_cntr--;

	http->request.url_offset = 0;
	get_more_headers(msg);
	return;
}

__attribute__((noinline)) int post_http_event(ctx_md *msg)
{
	struct socketmap_value *process;
	struct msg_http_event *http;
	__u32 skip = 0;
	__u64 cookie;
	size_t size;

	http = get_http_context(msg);
	if (unlikely(!http))
		return 0;

	cookie = (u64)msg->sk;
	process = lookup_socketmap(&cookie);
	if (!process)
		return 0;

	http->request.state = http_done;
	http->execve.pid = process->key.pid;
	http->execve.pad[0] = 0;
	http->execve.pad[1] = 0;
	http->execve.pad[2] = 0;
	http->execve.pad[3] = 0;
	http->execve.ktime = process->key.ktime;

	if (http->request.method == http_method_response)
		http->request.recv_cntr++;
	else
		http->request.send_cntr++;

	http->request.flags &= ~HTTP_MORE_HEADERS_NEEDED;
	http->common.ktime = ktime_get_ns();
	http->common.op = ISO_MSG_OP_HTTP;
	http->common.size = sizeof(struct __msg_http_event);
	http->tuple = process->tuple;

	size = sizeof(struct __msg_http_event);
	perf_event_output_metric(msg, ISO_MSG_OP_HTTP, &tcpmon_map, BPF_F_CURRENT_CPU, http, size);
	skip = http->request.consume_bytes + http->request.offset;
	http_reset_state(&http->request);
#ifdef SK_MSG
	msg_apply_bytes(msg, skip);
#else
	sk_skb_eat_bytes(msg, http, skip);
#endif
	return 0;
}

static inline __attribute__((always_inline)) int
http_do_parser(ctx_md *msg)
{
	struct msg_http_event *http;

	http = get_http_context(msg);
	if (unlikely(!http))
		return 0;

	if (!is_expected_request(&http->request)) {
		return 0;
	}

#ifndef SK_MSG
	if (http->request.consume_bytes) {
		sk_skb_eat_bytes(msg, http, http->request.consume_bytes);
		return 0;
	}
#endif

	http_parse(msg, http);
	return 0;
}

#endif // _HTTP_PARSER_
