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

#define SK_SKB

#include "http_parser.h"
#include "http2_parser.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

__attribute__((section("sk_skb/stream_verdict/fgshttp"), used)) int
tg_skskb_http_verdict(struct __sk_buff *skb)
{
	struct msg_tls_ip key = { 0 };

	msg_tls_tuple(skb, &key);
	return http_do_parser(skb, &key);
}

__attribute__((section("sk_skb/stream_verdict/0"), used)) int
tg_skskb_http_response(struct __sk_buff *skb)
{
	struct msg_tls_ip key = { 0 };
	struct msg_http_event *http;

	msg_tls_tuple(skb, &key);
	http = get_http_context(&key);
	if (unlikely(!http))
		return SK_PASS;

	http_parse_response(skb, &key, http, &http->request);
	if (http->request.state == http_more_headers_needed ||
	    http->request.state == http_more_headers_value_needed)
		return SK_PASS;
	post_http_event(skb, &key, http);
	return SK_PASS;
}

__attribute__((section("sk_skb/stream_verdict/1"), used)) int
tg_skskb_http_request(struct __sk_buff *skb)
{
	struct msg_tls_ip key = { 0 };
	struct msg_http_event *http;

	msg_tls_tuple(skb, &key);
	http = get_http_context(&key);
	if (unlikely(!http))
		return SK_PASS;

	http_parse_request(skb, &key, http);
	if (http->request.state == http_more_headers_needed ||
	    http->request.state == http_more_headers_value_needed)
		return SK_PASS;
	post_http_event(skb, &key, http);
	return SK_PASS;
}

__attribute__((section("sk_skb/stream_verdict/2"), used)) int
tg_skskb_get_more_headers(struct __sk_buff *skb)
{
	struct msg_tls_ip key = { 0 };
	struct msg_http_event *http;

	msg_tls_tuple(skb, &key);
	http = get_http_context(&key);
	if (unlikely(!http))
		return SK_PASS;
	http->request.state = http_get_headers;
	find_host_header(skb, &key, http, &http->request);
	if (http->request.state == http_more_headers_needed ||
	    http->request.state == http_more_headers_value_needed)
		return SK_PASS;
	post_http_event(skb, &key, http);
	return SK_PASS;
}

__attribute__((section("sk_skb/stream_verdict/3"), used)) int
tg_skskb_http2(struct __sk_buff *skb)
{
	struct msg_tls_ip key = { 0 };

	msg_tls_tuple(skb, &key);
	http2_do_parser(skb, &key);
	return SK_PASS;
}
