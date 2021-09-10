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

#include "http_parser.h"
#include "http2_parser.h"

__attribute__((section(("sk_msg/fgs")), used))
int bpf_http_sk_msg_fgs(struct sk_msg_md *msg)
{
	struct msg_tls_ipv4 tuple = {0};

	msg_tls_key(msg, &tuple);
	tuple.remaining = HTTP_SEND;
	return http_do_parser(msg, &tuple);
}

__attribute__((section(("sk_msg/0")), used))
int bpf_http_sk_msg_fgs_response(struct sk_msg_md *msg)
{
	struct msg_tls_ipv4 tuple = {0};
	struct msg_http *http;

	msg_tls_key(msg, &tuple);
	http = get_http_context(&tuple);
	if (unlikely(!http))
		return SK_PASS;

	http_parse_response(msg, http);
	http->state = http_done;
	if (http->state == http_done)
		post_http_event(msg, &tuple, http);
	return SK_PASS;
}

__attribute__((section(("sk_msg/1")), used))
int bpf_http_sk_msg_fgs_request(struct sk_msg_md *msg)
{
	struct msg_tls_ipv4 tuple = {0};
	struct msg_http *http;

	msg_tls_key(msg, &tuple);
	http = get_http_context(&tuple);
	if (unlikely(!http))
		return SK_PASS;

	http_parse_request(msg, http);
	http->state = http_done;
	if (http->state == http_done)
		post_http_event(msg, &tuple, http);
	return SK_PASS;
}

__attribute__((section(("sk_msg/2")), used))
int bpf_http_sk_msg_get_more_headers(struct sk_msg_md *msg)
{
	struct msg_tls_ipv4 tuple = {0};
	struct msg_http *http;

	msg_tls_key(msg, &tuple);
	http = get_http_context(&tuple);
	if (unlikely(!http))
		return SK_PASS;
	find_host_header(msg, http);
	http->state = http_done;
	if (http->state == http_done)
		post_http_event(msg, &tuple, http);
	return SK_PASS;
}

__attribute__((section(("sk_msg/3")), used))
int bpf_skmsg_http2(struct sk_msg_md *msg)
{
	struct msg_tls_ipv4 tuple = {0};

	msg_tls_key(msg, &tuple);
	return http2_do_parser(msg, &tuple);
}

char _license[] __attribute__((section(("license")), used)) = "GPL";
