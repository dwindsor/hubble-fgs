#ifndef _HTTP2_PARSER_
#define _HTTP2_PARSER_

#include "http_parser.h"

#undef HTTP2_DEBUG
// #define HTTP2_DEBUG

#define HTTP2_MAX_FRAMES 8
#define HTTP2_FRAME_HEADER_LENGTH 9
#define HTTP2_PREFACE_LENGTH 24

enum {
	HTTP2_FRAME_TYPE_DATA          = 0x0,
	HTTP2_FRAME_TYPE_HEADERS       = 0x1,
	HTTP2_FRAME_TYPE_PRIORITY      = 0x2,
	HTTP2_FRAME_TYPE_RST_STREAM    = 0x3,
	HTTP2_FRAME_TYPE_SETTINGS      = 0x4,
	HTTP2_FRAME_TYPE_PUSH_PROMISE  = 0x5,
	HTTP2_FRAME_TYPE_PING          = 0x6,
	HTTP2_FRAME_TYPE_GOAWAY        = 0x7,
	HTTP2_FRAME_TYPE_WINDOW_UPDATE = 0x8,
	HTTP2_FRAME_TYPE_CONTINUATION  = 0x9,
};

enum {
	HTTP2_FLAG_END_STREAM  = 0x1,
	HTTP2_FLAG_END_HEADERS = 0x4,
	HTTP2_FLAG_PADDED      = 0x8,
	HTTP2_FLAG_PRIORITY    = 0x20,
};

struct bpf_map_def __attribute__((section("maps"), used)) http2_heap = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(int),
	.value_size = 8192,
	.max_entries = 1,
};


#ifdef HTTP2_DEBUG
#define DBG(__fmt, ...) bpf_printk(__fmt, ##__VA_ARGS__)
#else
#define DBG(__fmt, ...)
#endif

#ifdef SK_SKB
static inline __attribute__((always_inline))
u8 *get_header_bytes(struct __sk_buff *skb, __u32 offset)
{
	int err, zero = 0;

	u8 *to = map_lookup_elem(&http2_heap, &zero);
	if (!to)
		return 0;

	asm volatile ("%[offset] &= 0x1ff;\n": [offset] "+r"(offset)::);
	err = skb_load_bytes(skb, offset, to, HTTP2_FRAME_HEADER_LENGTH);
	if (err)
		return 0;

	return to;
}
#else
static inline __attribute__((always_inline))
u8 *get_header_bytes(struct sk_msg_md *msg, __u32 offset)
{
	int err;

	asm volatile ("%[offset] &= 0x1ff;\n": [offset] "+r"(offset)::);
	err = msg_pull_data(msg, offset, offset + HTTP2_FRAME_HEADER_LENGTH, 0);
	if (err) {
		// TODO(JM): Handle the situation where part of the data is available.
		return 0;
	}

	if (msg->data + HTTP2_FRAME_HEADER_LENGTH > (void*)(long)msg->data_end)
		return 0; 

	return (void*)(long)msg->data;
}
	
#endif

static inline __attribute__((always_inline))
int emit_headers(ctx_md *msg, struct msg_http *http, struct msg_tls_ipv4 *key, __u32 offset, __u32 length)
{
	u32 url_off = http->url_offset & 0xff;
	u32 *dst = (__u32*)&http->url[url_off];
	int err;

	if (http->url_offset + length + HTTP2_FRAME_HEADER_LENGTH + 8 + 8 /* for termination */ > sizeof(http->url)) {
		// TODO: data does not fit into the event. what to do? if we just skip we potentially mess up
		// header compression in the future!
		DBG("http->url full (off %d), skipping header frame copy\n", http->url_offset);
		return -1;
	}

	dst[0] = http2_header_frame;
	dst[1] = length + HTTP2_FRAME_HEADER_LENGTH;
	offset &= 0x1ff;
	length &= 0x1ff;

#ifdef SK_SKB
	err = skb_load_bytes(msg, offset, (void*)&dst[2], length + HTTP2_FRAME_HEADER_LENGTH);
	if (err)
		return -1;
#else
	err = msg_pull_data(msg, offset, offset + HTTP2_FRAME_HEADER_LENGTH + length, 0);
	if (err)
		return -1;

	u8 *data = (void*)(long)msg->data;
	u8 *data_end = (void*)(long)msg->data_end;

	if (data + HTTP2_FRAME_HEADER_LENGTH + length <= data_end) {
		pkt_copy((u8*)&dst[2],
		         data_end,
			 data, 
		         length + HTTP2_FRAME_HEADER_LENGTH);
	} else {
		return -1;
	}
#endif

	http->url_offset += 8 + length + HTTP2_FRAME_HEADER_LENGTH;
	dst = (__u32*)&http->url[http->url_offset & 0xff];
	dst[0] = 0;
	dst[1] = 0;

	post_http_event(msg, key, http);

	http->url_offset = 0;
	
	return 0;
}

static inline __attribute__((always_inline))
int http2_parse_frame(struct msg_http *http, struct msg_tls_ipv4 *key, ctx_md *msg, __u32 offset, bool *stop)
{
	u8 *data = get_header_bytes(msg, offset);
	if (!data) {
		// TODO(JM): Handle the partial write:
		// - stash the <9 bytes into http->scratch
		// - in get_header_bytes, read the remaining bytes into http->scratch and return ptr to it
		// - for copy_frame_to_event, look into http->offset and copy from there as needed
		*stop = 1;
		return 0;
	}

	u32 length = *data << 16 | *(data + 1) << 8 | *(data + 2);
	u8 type = *(data + 3);
	u8 flags = *(data + 4);

#ifdef HTTP2_DEBUG
	u32 stream_id = (*(data + 5) & 0x7f) << 24 | *(data + 6) << 16 | *(data + 7) << 8 | *(data + 8);
	DBG("Found frame: offset=%d, type=%d, length=%d\n", offset, type, length);
	DBG("...........  stream_id=%d, flags=%d\n", stream_id, flags);
#endif

	switch (type) {
	case HTTP2_FRAME_TYPE_HEADERS: {
		if (flags & HTTP2_FLAG_END_HEADERS) {
			if (emit_headers(msg, http, key, offset, length)) {
				// TODO(JM): How to handle failure here? Due to header compression
				// we may not be able to read future frames in this stream so likely
				// best to stop.
				http->state = http_error;
				*stop = 1;
				return 0;
			}
		} else {
			// TODO(JM): Headers are split into multiple frames. We don't handle
			// that yet, so stop.
			// To handle it correctly we'd need to store the frames somewhere
			// (keyed by stream id) and then emit when we see END_HEADERS.
			DBG("HTTP2 headers frame found, but it is split. Bailing out.\n", 0);
			http->state = http_error;
			*stop = 1;
			return 0;
		}
		break;
	}

#ifdef SK_MSG
	case HTTP2_FRAME_TYPE_DATA:
		if (length > 256) {
			/* Large payload, apply verdict and resume after this frame. */
			// TODO(JM): This is untested.
			msg_apply_bytes(msg, offset + HTTP2_FRAME_HEADER_LENGTH + length);
			*stop = 1;
			return 0;
		}
		break;
#endif
	default: 
		break;
	}

	return HTTP2_FRAME_HEADER_LENGTH + length;
}

static inline __attribute__((always_inline))
bool http2_is_preface(ctx_md *msg)
{
	u8 preface[HTTP2_PREFACE_LENGTH] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
	u8 *data = (void*)(long)msg->data;

	// TODO(JM): Should pull data?

	if (data + HTTP2_PREFACE_LENGTH > (void*)(long)msg->data_end)
		return false;

#pragma unroll
	for (int i = 0; i < HTTP2_PREFACE_LENGTH; i++) {
		if (data[i] != preface[i])
			return false;
	}
	return true;
}

static inline __attribute__((always_inline))
int http2_do_parser(ctx_md *msg, struct msg_tls_ipv4 *tuple)
{
	struct msg_http *http;
	bool stop = false;
	u32 offset = 0;

	http = get_http_context(tuple);
	if (unlikely(!http))
		return SK_PASS;

	switch (http->state) {
	case http2_expect_preface:
		if (!http2_is_preface(msg)) {
			DBG("Expected HTTP/2 preface, but didn't find it.\n", 0);
			http->state = http_error;
			return SK_PASS;
		}
		offset += HTTP2_PREFACE_LENGTH;
		http->state = http2_expect_frame;
		break;

	case http2_expect_frame:
		break;
		
	default:
		DBG("http2_parser: Unhandled state %d\n", http->state);
		http->state = http_error;
		return SK_PASS;
	}

#pragma unroll
	for (int frame = 0; frame < HTTP2_MAX_FRAMES; frame++) {
		offset += http2_parse_frame(http, tuple, msg, offset, &stop);
		if (stop) return SK_PASS;
	}

	/* Give up when we cannot parse all the frames to avoid desyncing 
         * the HPACK decoder */
	DBG("http2_parser: Too many frames in message, giving up!\n", 0);
	http->state = http_error;
	return SK_PASS;
}

#endif /* _HTTP2_PARSER_ */ 

