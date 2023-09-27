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
#define HTTP_DIR HTTP_SEND

#include "http_parser.h"
#include "http2_parser.h"

__attribute__((section("sk_msg/fgs"), used)) int
tg_http_sk_msg_fgs(struct sk_msg_md *msg)
{

	/* Workaround to clear any applied bytes from
         * previous execution on the same message. */
	msg_apply_bytes(msg, 0);

	http_do_parser(msg);
	return SK_PASS;
}

__attribute__((section("sk_msg/0"), used)) int
tg_http_sk_msg_fgs_response(struct sk_msg_md *msg)
{
	int post = http_parse_response(msg);

	if (post)
		post_http_event(msg);
	return SK_PASS;
}

__attribute__((section("sk_msg/1"), used)) int
tg_http_sk_msg_fgs_request(struct sk_msg_md *msg)
{
	int post = http_parse_request(msg);

	if (post)
		post_http_event(msg);
	return SK_PASS;
}

__attribute__((section("sk_msg/2"), used)) int
tg_http_sk_msg_get_more_headers(struct sk_msg_md *msg)
{
	struct msg_http_event *http;

	http = get_http_context(msg);
	if (unlikely(!http))
		return SK_PASS;
	http->request.state = http_get_headers;
	find_host_header(msg, http, &http->request);
	return SK_PASS;
}

__attribute__((section("sk_msg/3"), used)) int
tg_skmsg_http2(struct sk_msg_md *msg)
{
	return http2_do_parser(msg);
}

char _license[] __attribute__((section("license"), used)) = "GPL";
