// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef __HTTP_H_
#define __HTTP_H_

#include "../../lib/tlsmsg.h"
#include "bpf_helpers.h"

// State enum for HTTP state stats.
// NOTE: Remember to update HttpStateNames in httpapi.go when you add a new state type here
enum http_state {
	// Unknown HTTP method
	http_state_unkown_method,
	// Missing HTTP context
	http_state_missing_http_context,
	// Missing process info
	http_state_missing_process_info,
	// Unknown HTTP header
	http_state_unknown_header,
	// Must be last
	__http_state_max,
};

enum http_method {
	// data read error
	http_method_error,

	// list of supported http methods
	http_method_connect,
	http_method_delete,
	http_method_get,
	http_method_head,
	http_method_options,
	http_method_post,
	http_method_put,
	http_method_patch,
	http_method_trace,

	// list of method errors
	http_method_unknown,

	// use pseudo method response to indicate status line
	http_method_response,

	// a PRI method, likely HTTP/2 with prior knowledge
	http_method_pri,

	// split http method, need to see more packets
	http_method_split,
};

enum http_request_header {
	http_request__unused,
	http_request_url,
	http_request_host,
	http_request_protocol,
	http_request_header,
	http_request_user_agent,
	http_request_content_length,
	http_request_unknown,
	http_response_protocol,
	http_response_code,
	http_response_reason,
	http2_header_frame,
	http_request_transfer_encoding,
};

#define chr_sp	  ' '
#define chr_r	  '\r'
#define chr_n	  '\n'
#define chr_colon ':'

enum http_request_state {
	http_start,
	http_req_method_start,
	http_req_method_cont,
	http_done,
	http_error,

	http_get_headers,
	http_more_headers_needed,
	http_more_headers_value_needed,

	http_request_state_method_split,

	/* when state is above this we tail-call into http2 parser */

	http2_expect_preface,
	http2_expect_frame,
};

#define HTTP_MORE_HEADERS_NEEDED 0x1

struct __msg_http {
	__u32 method;
	__u32 flags;
	/* counters to use for IDs in sender and receiver
	 * side. These must only be used under sock_lock
	 * to ensure single reader/writer.
	 */
	__u64 send_cntr;
	__u64 recv_cntr;
	__u64 url_length;
};

struct msg_http {
	__u32 method;
	__u32 flags;
	/* counters to use for IDs in sender and receiver
	 * side. These must only be used under sock_lock
	 * to ensure single reader/writer.
	 */
	__u64 send_cntr;
	__u64 recv_cntr;
	__u64 url_length;
	char url[1024];
	// Below is BPF parser pushed to user space to allow debugging
	__u32 state;
	__u32 offset;
	__u32 url_offset;
	__u32 url_continue;
	__u64 consume_bytes;
	// Below is internal only state and is not pushed to userspace.
	char scratch[512]; // extra space
};

struct msg_http_event {
	struct msg_common common;
	__u64 socket_cookie;
	__u64 socket_version;
	struct msg_ip_tuple tuple;
	struct msg_execve_key execve;
	struct msg_http request;
} __attribute__((packed));

struct __msg_http_event {
	struct msg_common common;
	__u64 socket_cookie;
	__u64 socket_version;
	struct msg_ip_tuple tuple;
	struct msg_execve_key execve;
	struct __msg_http request;
} __attribute__((packed));

struct __http_state_stats {
	__u64 cnt[__http_state_max];
};

#ifndef ALIGNCHECKER
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct msg_http_event);
	__uint(max_entries, 1000);
} tg_http_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct msg_http_event);
	__uint(max_entries, 1);
} tg_http_map_heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct __http_state_stats);
	__uint(max_entries, 1);
} tg_http_err_stats SEC(".maps");

static inline __attribute__((always_inline)) void http_state_inc(enum http_state state)
{
	int zero = 0;
	struct __http_state_stats *stats;

	stats = map_lookup_elem(&tg_http_err_stats, &zero);
	if (stats)
		stats->cnt[state]++;
}
#endif // ALIGNCHECKER

#endif