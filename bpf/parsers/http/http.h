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
};

enum http_request_header {
	http_request_done,
	http_request_url,
	http_request_host,
	http_request_protocol,
	http_request_header,
	http_request_user_agent,
	http_request_content_length,
	http_request_unknown,
	http_response_protocol,
	http_response_code,
	http_response_reason
};

#define chr_sp	   ' '
#define chr_r	   '\r'
#define chr_n	   '\n'
#define chr_colon  ':'

#define http_hdr_host   "Host"
#define http_hdr_user   "User-Agent"
#define http_hdr_type   "Content-Type"
#define http_hdr_length "Content-Length"

// list of supported http methods offsets
#define http_method_connect_off  sizeof("connect")
#define http_method_delete_off   sizeof("delete")
#define http_method_get_off      sizeof("get")
#define http_method_head_off     sizeof("head")
#define http_method_options_off  sizeof("options")
#define http_method_post_off     sizeof("post")
#define http_method_put_off	 sizeof("put")
#define http_method_patch_off	 sizeof("patch")
#define http_method_trace_off	 sizeof("trace")

// Supported header fields
#define HOST      {'H', 'o', 's', 't'};
#define USERAGENT {'U','s','e','r','-','A','g','e','n','t'}
#define CONTENT   {'C','o','n','t','e','n','t','-','l','e','n','g','t','h'}

enum http_request_state {
	http_start,
	http_req_method_start,
	http_req_method_cont,
	http_done,
	http_error,
};

struct __msg_http {
	__u32 method;
	char url[256]; //tbd optimize to dynamic length
	// below is private state for BPF parser
	__u32 state;
	__u32 offset;
	__u32 url_offset;
} __attribute__((packed));

struct msg_http {
	__u32 method;
	char url[256]; //tbd optimize to dynamic length
	// below is private state for BPF parser
	__u32 state;
	__u32 offset;
	__u32 url_offset;
	char scratch[512]; // extra space
} __attribute__((packed));

struct msg_http_event {
	struct msg_common     common;
	struct msg_tls_ipv4   tuple;
	struct msg_execve_key execve;
	struct msg_http	      request;
} __attribute__((packed));

struct __msg_http_event {
	struct msg_common     common;
	struct msg_tls_ipv4   tuple;
	struct msg_execve_key execve;
	struct __msg_http     request;
} __attribute__((packed));

struct bpf_map_def __attribute__((section("maps"), used)) http_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct msg_tls_ipv4),
	.value_size = sizeof(struct msg_http),
	.max_entries = 1000,
};

struct bpf_map_def __attribute__((section("maps"), used)) http_map_heap = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(struct msg_http),
	.max_entries = 1,
};

struct bpf_map_def __attribute__((section("maps"), used)) http_event_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(struct msg_http_event),
	.max_entries = 1,
};
