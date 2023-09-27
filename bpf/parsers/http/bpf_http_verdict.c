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
#define HTTP_DIR HTTP_RECV

#include "http_parser.h"
#include "http2_parser.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

__attribute__((section("sk_skb/stream_verdict/fgshttp"), used)) int
tg_skskb_http_verdict(struct __sk_buff *skb)
{
	http_do_parser(skb);
	return SK_PASS;
}

__attribute__((section("sk_skb/stream_verdict/0"), used)) int
tg_skskb_http_response(struct __sk_buff *skb)
{
	int post = http_parse_response(skb);

	if (post)
		post_http_event(skb);
	return SK_PASS;
}

__attribute__((section("sk_skb/stream_verdict/1"), used)) int
tg_skskb_http_request(struct __sk_buff *skb)
{
	int post = http_parse_request(skb);

	if (post)
		post_http_event(skb);
	return SK_PASS;
}

__attribute__((section("sk_skb/stream_verdict/2"), used)) int
tg_skskb_get_more_headers(struct __sk_buff *skb)
{
	struct msg_http_event *http;

	http = get_http_context(skb);
	if (unlikely(!http))
		return SK_PASS;
	http->request.state = http_get_headers;
	find_host_header(skb, http, &http->request);
	return SK_PASS;
}

__attribute__((section("sk_skb/stream_verdict/3"), used)) int
tg_skskb_http2(struct __sk_buff *skb)
{
	http2_do_parser(skb);
	return SK_PASS;
}
