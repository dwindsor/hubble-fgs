// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef __BPF_TCP_STATE_H__
#define __BPF_TCP_STATE_H__

#include "vmlinux.h"

#include "api.h"
#include "bpf_event.h"
#include "bpf_network_helpers.h"
#include "bpf_tcp_send_check.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct msg_ip_with_stats_event);
	__uint(max_entries, 1);
} tcp_close_event_map SEC(".maps");

static inline int
tcp_set_fin(void *ctx, u64 *cookie)
{
	struct tcpsocketmap_value *socket;

	socket = lookup_tcpsocketmap(cookie);
	if (!socket) {
		emit_ip_error_event(ctx, 0, cookie, false, 0, 0, 0, IP_ERROR_TCP_CLOSE_NO_SOCKET);
		return 0;
	}

	/* When a socket is closing, it may have received a FIN(/ACK) segment.
	* Unfortunately, a FIN(/ACK) increases the received sequence counter
	* by 1 (in order to maintain appropriate state). We use the received
	* sequence counter to indicate the number of bytes received, so if
	* we have received a FIN(/ACK) then our counter will be 1 greater than
	* it should be. Mark the socket so that stats calculations can take
	* this into account.
	*/
	socket->fin_rx = 1;
	return 0;
}
#endif // __BPF_TCP_STATE_H__
