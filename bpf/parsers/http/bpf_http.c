// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#include "vmlinux.h"
#include "api.h"

#define SK_MSG

#include "http_parser.h"
#include "http2_parser.h"

__attribute__((section("sk_msg/fgs"), used)) int
bpf_http_sk_msg_fgs(struct sk_msg_md *msg)
{
	struct msg_tls_ipv4 tuple = { 0 };

	/* Workaround to clear any applied bytes from
         * previous execution on the same message. */
	msg_apply_bytes(msg, 0);

	msg_tls_key(msg, &tuple);
	return http_do_parser(msg, &tuple);
}

__attribute__((section("sk_msg/0"), used)) int
bpf_http_sk_msg_fgs_response(struct sk_msg_md *msg)
{
	struct msg_tls_ipv4 tuple = { 0 };
	struct msg_http_event *http;

	msg_tls_key(msg, &tuple);
	http = get_http_context(&tuple);
	if (unlikely(!http))
		return SK_PASS;

	http_parse_response(msg, &tuple, http, &http->request);
	if (http->request.state == http_more_headers_needed ||
	    http->request.state == http_more_headers_value_needed)
		return SK_PASS;
	http->request.state = http_done;
	post_http_event(msg, &tuple, http);
	return SK_PASS;
}

__attribute__((section("sk_msg/1"), used)) int
bpf_http_sk_msg_fgs_request(struct sk_msg_md *msg)
{
	struct msg_tls_ipv4 tuple = { 0 };
	struct msg_http_event *http;

	msg_tls_key(msg, &tuple);
	http = get_http_context(&tuple);
	if (unlikely(!http))
		return SK_PASS;

	http_parse_request(msg, &tuple, http);
	if (http->request.state == http_more_headers_needed ||
	    http->request.state == http_more_headers_value_needed)
		return SK_PASS;
	http->request.state = http_done;
	post_http_event(msg, &tuple, http);
	return SK_PASS;
}

__attribute__((section("sk_msg/2"), used)) int
bpf_http_sk_msg_get_more_headers(struct sk_msg_md *msg)
{
	struct msg_tls_ipv4 tuple = { 0 };
	struct msg_http_event *http;

	msg_tls_key(msg, &tuple);
	http = get_http_context(&tuple);
	if (unlikely(!http))
		return SK_PASS;
	http->request.state = http_get_headers;
	find_host_header(msg, &tuple, http, &http->request);
	if (http->request.state == http_more_headers_needed ||
	    http->request.state == http_more_headers_value_needed)
		return SK_PASS;
	http->request.state = http_done;
	post_http_event(msg, &tuple, http);
	return SK_PASS;
}

__attribute__((section("sk_msg/3"), used)) int
bpf_skmsg_http2(struct sk_msg_md *msg)
{
	struct msg_tls_ipv4 tuple = { 0 };

	msg_tls_key(msg, &tuple);
	return http2_do_parser(msg, &tuple);
}

char _license[] __attribute__((section("license"), used)) = "GPL";
