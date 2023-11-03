// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef _HTTP2_PARSER_
#define _HTTP2_PARSER_

#include "http_parser.h"

#define HTTP2_MAX_FRAMES	  8
#define HTTP2_FRAME_HEADER_LENGTH 9
#define HTTP2_PREFACE_LENGTH	  24

enum {
	HTTP2_FRAME_TYPE_DATA = 0x0,
	HTTP2_FRAME_TYPE_HEADERS = 0x1,
	HTTP2_FRAME_TYPE_PRIORITY = 0x2,
	HTTP2_FRAME_TYPE_RST_STREAM = 0x3,
	HTTP2_FRAME_TYPE_SETTINGS = 0x4,
	HTTP2_FRAME_TYPE_PUSH_PROMISE = 0x5,
	HTTP2_FRAME_TYPE_PING = 0x6,
	HTTP2_FRAME_TYPE_GOAWAY = 0x7,
	HTTP2_FRAME_TYPE_WINDOW_UPDATE = 0x8,
	HTTP2_FRAME_TYPE_CONTINUATION = 0x9,
};

enum {
	HTTP2_FLAG_END_STREAM = 0x1,
	HTTP2_FLAG_END_HEADERS = 0x4,
	HTTP2_FLAG_PADDED = 0x8,
	HTTP2_FLAG_PRIORITY = 0x20,
};

/* Helpers for accessing the "typed chunks" stored in (struct msg_http).url */
#define NULL_CHUNK_EVENT_SZ 8

struct http_event_chunk {
	u32 type;
	u32 length;
	u8 data[0];
} __attribute__((packed));

static inline __attribute__((always_inline)) struct http_event_chunk *
head_chunk(struct msg_http *http)
{
	return (struct http_event_chunk *)&http->url[0];
}

/* Helpers for accessing the context, whether it's a sk_buff or sk_msg_md. */
#ifdef SK_MSG
static inline __attribute__((always_inline)) void *
ctx_data(ctx_md *msg)
{
	void *data;

	/* NOTE(JM): llvm emits wrong code that modifies context ptr:
         * r1 = ctx; r1 += 76; r2 = *(u64*)r1 */
	asm volatile("%[data] = *(u64 *)(%[msg] + 0);\n"
		     : [data] "=&r"(data)
		     : [msg] "r"(msg)
		     :);

	return data;
}
static inline __attribute__((always_inline)) void *
ctx_data_end(ctx_md *msg)
{
	void *data_end;
	asm volatile("%[data_end] = *(u64 *)(%[msg] + 8);\n"
		     : [data_end] "=&r"(data_end)
		     : [msg] "r"(msg)
		     :);
	return data_end;
}

static inline __attribute__((always_inline)) u32 ctx_len(ctx_md *msg)
{
	u32 size;
	asm volatile("%[size] = *(u32 *)(%[msg] + 68);\n"
		     : [size] "=&r"(size)
		     : [msg] "r"(msg)
		     :);
	return size;
}
#define ctx_pull_data(ctx, len) msg_pull_data((ctx), 0, (len), 0)
#else
static inline __attribute__((always_inline)) void *
ctx_data(struct __sk_buff *skb)
{
	void *data;

	/* NOTE(JM): llvm emits wrong code that modifies context ptr:
         * r1 = ctx; r1 += 76; r2 = *(u64*)r1 */
	asm volatile("%[data] = *(u32 *)(%[skb] + 76);\n"
		     : [data] "=&r"(data)
		     : [skb] "r"(skb)
		     :);

	return data;
}

static inline __attribute__((always_inline)) void *
ctx_data_end(struct __sk_buff *skb)
{
	void *data_end;
	asm volatile("%[data_end] = *(u32 *)(%[skb] + 80);\n"
		     : [data_end] "=&r"(data_end)
		     : [skb] "r"(skb)
		     :);
	return data_end;
}

#define ctx_len(msg)		(msg)->len
#define ctx_pull_data(msg, len) skb_pull_data((msg), (len))
#endif

enum chunk_status {
	CHUNK_OK, /* Chunk is now complete and contains the requested amount of bytes. */
	CHUNK_EOF, /* End of message encountered and chunk is still incomplete. */
	CHUNK_OVERFLOW, /* Target buffer would overflow */
	CHUNK_ERROR,
};

/* append_to_chunk appends bytes from given offset to the head chunk. Returns
 * CHUNK_OK when the chunk's length reaches 'len', or CHUNK_EOF if the message is
 * too short to reach the target length.
 */
static inline __attribute__((always_inline)) enum chunk_status
append_to_chunk(ctx_md *skb, struct msg_http *http, u32 len)
{
	struct http_event_chunk *chunk = head_chunk(http);
	u32 chunk_len = chunk->length & 0x1ff;
	u32 offset = http->offset;
	u32 requested = len - chunk_len;

	DEBUG("append_to_chunk, offset=%d, len=%d, chunk_len=%d", offset, len,
	      chunk_len);

	if (chunk_len >= len) {
		/* Chunk already full */
		return CHUNK_OK;
	}

	void *data = ctx_data(skb);
	void *data_end = ctx_data_end(skb);

	asm volatile("%[offset] &= 0x1ff;\n"
		     : [offset] "+r"(offset)::);
	asm volatile("%[requested] &= 0x1ff;\n"
		     : [requested] "+r"(requested)::);
	if (data + offset + requested > data_end) {
		if (requested > ctx_len(skb) - offset) {
			/* Append can be only partially satisfied, read whatever we can. */
			DEBUG("skb len=%d, trying to read %d", ctx_len(skb),
			      offset + requested);
			requested = (ctx_len(skb) - offset) & 0x1ff;
		}

		if (!requested)
			return CHUNK_EOF;

		int err = ctx_pull_data(skb, offset + requested);
		if (err) {
			DEBUG("unexpected: skb_pull_data(%d) failed with %d",
			      offset + requested, err);
			return CHUNK_ERROR;
		}

		data = ctx_data(skb);
		data_end = ctx_data_end(skb);
	}

	/* Recheck bounds */
	asm volatile("%[offset] &= 0x1ff;\n"
		     : [offset] "+r"(offset)::);
	asm volatile("%[requested] &= 0x1ff;\n"
		     : [requested] "+r"(requested)::);
	if (data + offset + requested > data_end) {
		DEBUG("unexpected: data still not available! ctx->len = %d",
		      ctx_len(skb));
		DEBUG("offset = %d, requested = %d, linear = %d", offset,
		      requested, data_end - data);
		return CHUNK_ERROR;
	}

	asm volatile("%[chunk_len] &= 0x1ff;\n"
		     : [chunk_len] "+r"(chunk_len)::);
	void *to = chunk->data + chunk_len;

	if (to + requested > &http->url[sizeof(http->url) - 8])
		return CHUNK_OVERFLOW;

	pkt_copy(to, data_end, data + offset, requested);

	DEBUG("copied %d bytes into chunk", requested);

	chunk->length += requested;
	http->offset += requested;
	http->url_length += requested;

	if (chunk->length >= len) {
		/* Chunk is now complete */
		return CHUNK_OK;
	} else {
		return CHUNK_EOF;
	}
}

static inline __attribute__((always_inline)) void
post_http2_event(ctx_md *msg, struct msg_http_event *event)
{
	struct msg_http *http = &event->request;
	struct socketmap_value *process;
	u64 cookie = (u64)msg->sk;
	size_t size;

	process = lookup_socketmap(&cookie);
	if (!process)
		return;

	event->execve.pid = process->key.pid;
	event->execve.pad[0] = 0;
	event->execve.pad[1] = 0;
	event->execve.pad[2] = 0;
	event->execve.pad[3] = 0;
	event->execve.ktime = process->key.ktime;

	/* Terminate the chunk */
	struct http_event_chunk *chunk = head_chunk(http);
	http->url_offset = sizeof(struct http_event_chunk) + chunk->length;
	if (http->url_offset + 8 < sizeof(http->url)) {
		chunk = (struct http_event_chunk *)&http
				->url[http->url_offset & 0x1ff];
		chunk->type = 0;
		chunk->length = 0;
	}

	http->url_length += sizeof(struct http_event_chunk) + NULL_CHUNK_EVENT_SZ;
	size = sizeof(struct __msg_http_event) + http->url_length;
	if (size > sizeof(struct msg_http_event))
		size = sizeof(struct msg_http_event);

	event->common.ktime = ktime_get_ns();
	event->common.op = ISO_MSG_OP_HTTP;
	event->common.size = size;
	event->tuple = process->tuple;

	/* Reuse the HTTP/1.1 send_cntr to assign a sequence number for each event we're sending. 
         * Due to per-cpu rings the events we send here may be read out-of-order in user-space. Because HTTP/2
         * header decompression is stateful we do need to process the frames in order. With the sequence number
         * we can reorder the frames.
         */
	http->send_cntr++;

	perf_event_output_metric(msg, ISO_MSG_OP_HTTP, &tcpmon_map, BPF_F_CURRENT_CPU, event, size);

	http->url_offset = 0;
	http->url_length = 0;
	chunk = head_chunk(http);
	chunk->type = 0;
	chunk->length = 0;
}

static inline __attribute__((always_inline)) int
emit_headers(ctx_md *msg, struct msg_http_event *event, u32 payload_length)
{
	struct msg_http *http = &event->request;

	/* Append the frame payload to the current chunk (which already has frame header) */
	switch (append_to_chunk(msg, http,
				HTTP2_FRAME_HEADER_LENGTH + payload_length)) {
	case CHUNK_OK:
		break;

	case CHUNK_EOF:
		DEBUG("EOF when reading frame payload (%d bytes, chunk now at %d)",
		      payload_length, head_chunk(http)->length);
		return 1;

	case CHUNK_OVERFLOW:
		/* FIXME(JM): Gracefully handle the overflow! */
	case CHUNK_ERROR:
		DEBUG("failed to append chunk", 0);
		event->request.state = http_error;
		return 1;
	}

	head_chunk(http)->type = http2_header_frame;
	post_http2_event(msg, event);

	return 0;
}

static inline __attribute__((always_inline)) bool
http2_parse_frame(ctx_md *msg, struct msg_http_event *event)
{
	struct msg_http *http = &event->request;

	/* Try to append the frame header to chunk */
	switch (append_to_chunk(msg, http, HTTP2_FRAME_HEADER_LENGTH)) {
	case CHUNK_OK:
		break;
	case CHUNK_EOF:
		DEBUG("EOF when reading frame header (chunk now at %d)",
		      head_chunk(http)->length);
		return true;
	case CHUNK_OVERFLOW:
	case CHUNK_ERROR:
		DEBUG("failed to append header to chunk", 0);
		http->state = http_error;
		return true;
	}

	u8 *data = head_chunk(http)->data;
	u32 length = *data << 16 | *(data + 1) << 8 | *(data + 2);
	u8 type = *(data + 3);
	u8 flags = *(data + 4);

#ifdef HTTP2_DEBUG
	u32 stream_id = (*(data + 5) & 0x7f) << 24 | *(data + 6) << 16 |
			*(data + 7) << 8 | *(data + 8);
	DEBUG("Found frame: offset=%d, type=%d, length=%d", http->offset, type,
	      length);
	DEBUG("...........  stream_id=%d, flags=%d", stream_id, flags);
#endif
	switch (type) {
	case HTTP2_FRAME_TYPE_HEADERS: {
		if (flags & HTTP2_FLAG_END_HEADERS) {
			if (emit_headers(msg, event, length)) {
				/* Could not yet emit the event, stop and return back later. */
				return true;
			}
		} else {
			// TODO(JM): Headers are split into multiple frames. We don't handle
			// that yet, so stop.
			// To handle it correctly we'd need combine the multiple header frames in
			// user-space and then decode them in one go.
			DEBUG("HTTP2 headers frame found, but it is split. Bailing out.",
			      0);
			http->state = http_error;
			return true;
		}
		break;
	}

	default:
		/* Discard the header copied into the chunk and skip over this frame. */
		head_chunk(http)->length = 0;

		u32 skip = http->offset + length;
#ifdef SK_MSG
		DEBUG("MSG skip %d bytes", skip);
		msg_apply_bytes(msg, skip);
#else
		DEBUG("SKB skip %d bytes", skip);
		sk_skb_eat_bytes(msg, event, skip);
#endif
		return true;
	}

	return false;
}

static inline __attribute__((always_inline)) int
http2_is_preface(ctx_md *msg, struct msg_http *http)
{
	u8 preface[HTTP2_PREFACE_LENGTH] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
	u8 *data = head_chunk(http)->data;

	switch (append_to_chunk(msg, http, HTTP2_PREFACE_LENGTH)) {
	case CHUNK_OK:
#pragma unroll
		for (int i = 0; i < HTTP2_PREFACE_LENGTH; i++) {
			if (data[i] != preface[i])
				return 1;
		}
		return 0;

	case CHUNK_ERROR:
	case CHUNK_OVERFLOW:
		DEBUG("http2_is_preface: Error or overflow", 0);
		http->state = http_error;
	case CHUNK_EOF:
		return -1;
	}
}

static inline __attribute__((always_inline)) int
http2_do_parser(ctx_md *msg)
{
	struct msg_http_event *event;
	struct msg_http *http;

	event = get_http_context(msg);
	if (unlikely(!event)) {
		return SK_PASS;
	}
	http = &event->request;

#ifdef SK_MSG
	DEBUG("MSG http2_do_parser: len %d, skip %d, consume %d", ctx_len(msg),
	      http->offset, http->consume_bytes);
#else
	DEBUG("SKB http2_do_parser: len %d, skip %d, consume %d", ctx_len(msg),
	      http->offset, http->consume_bytes);
#endif

#ifndef SK_MSG
	if (http->consume_bytes) {
		sk_skb_eat_bytes(msg, event, http->consume_bytes);
		return SK_PASS;
	}
#endif

	switch (http->state) {
	case http2_expect_preface:
		switch (http2_is_preface(msg, http)) {
		case 1:
			DEBUG("Expected HTTP/2 preface, but didn't find it.",
			      0);
			http->state = http_error;
			return SK_PASS;
		case -1:
			return SK_PASS;
		}
		head_chunk(http)->length = 0;
		http->state = http2_expect_frame;
		break;

	case http2_expect_frame:
		break;

	default:
		DEBUG("http2_parser: Unhandled state %d", http->state);
		http->state = http_error;
		return SK_PASS;
	}

#pragma unroll
	for (int frame = 0; frame < HTTP2_MAX_FRAMES; frame++) {
		if (http2_parse_frame(msg, event)) {
			DEBUG("STOP", 0);
			http->offset = 0;
			return SK_PASS;
		}
	}

	/* Give up when we cannot parse all the frames to avoid desyncing 
         * the HPACK decoder */
	DEBUG("http2_parser: Too many frames in message, giving up!", 0);
	http->offset = 0;
	http->state = http_error;

	return SK_PASS;
}

#endif /* _HTTP2_PARSER_ */
