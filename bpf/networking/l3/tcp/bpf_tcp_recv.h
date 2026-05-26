// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef __BPF_TCP_RECV_H_
#define __BPF_TCP_RECV_H_

#include "vmlinux.h"
#include "api.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "bpf_process_network_watermarks.h"
#include "bpf_cookie.h"
#include "bpf_network_helpers.h"
#include "bpf_tcp_send_check.h"
#include "lib/address_family.h"
#include "bpf_tracing.h"
#include "bpf_tcp_info.h"
#include "process/process_tree.h"

extern volatile __CONST bool CGROUP_PROBE_READ;

static inline __attribute__((always_inline)) bool
get_tcp_fin(struct __sk_buff *skb, void *ip, __u64 tcp_offset, __u64 *cookie, bool ipv6)
{
	__u64 data_end = skb->data_end;
	__u64 data = skb->data;
	struct tcphdr *tcp;
	struct tcphdr stor;

	if (data + (tcp_offset & 0x0fff) + sizeof(struct tcphdr) > data_end) {
		if (skb_load_bytes(skb, tcp_offset, &stor, sizeof(struct tcphdr)) < 0) {
			emit_ip_error_event(skb, ip, cookie, ipv6, 0, 1, 0, IP_ERROR_INET_READ_TCP);
			return false;
		}
		tcp = &stor;
	} else {
		tcp = (struct tcphdr *)(data + (tcp_offset & 0xfff));
	}
	return tcp->fin;
}

static inline __attribute__((always_inline)) int
tcp_check_fin_rx(struct __sk_buff *skb, void *ip, __u64 tcp_offset, __u64 *cookie, bool ipv6)
{
	bool tcpfin = get_tcp_fin(skb, ip, tcp_offset, cookie, ipv6);
	struct tcp_sock *tcp;
	__u64 bytes_received;
	__u64 c;

	// Only handle FIN datagrams.
	if (!tcpfin)
		return SK_PASS;

	if (!cookie)
		return SK_PASS;

	c = *cookie;
	tcp = (struct tcp_sock *)c;

	// There are a few situations in which we could have received a FIN:
	// 1) As the last packet from a peer. This is the normal FIN.
	// 2) As a genuine out-of-order FIN. Data packets will follow.
	// 3) As a rogue FIN that doesn't match the sequence number.
	// We cannot reliably tell which situation we are in without replicating
	// the kernel's checks. We can make the following assumptions, however:
	// a) If a FIN is ACKed, the received_bytes might be incremented.
	// b) If we receive multiple FINs for a socket, the last one is most
	// likely to be the genuine one, because after a genuine one the socket
	// is likely being shut down.
	// c) If at socket close the stack bytes_received is one more than the
	// bytes_received observed for the last FIN, then the stack value
	// includes an ACK; use the recorded value.
	// We can therefore record the bytes_received in the stack for every
	// FIN we see. When accounting, if the stack received_bytes is not one
	// more than the recorded received_bytes, use the stack value. This
	// will result in off-by-one errors in some connections where the FIN
	// arrived out-of-order. It will, however, protect against the majority
	// of rogue FINs, allowing a discrepancy of at most 1 byte (where a
	// rogue FIN was received after the real FIN but before the socket has
	// been destroyed).
	probe_read_kernel(&bytes_received, sizeof(bytes_received), _(&tcp->bytes_received));
	map_update_elem(&tg_l3_tcp_finrx, &c, &bytes_received, 0);

	return SK_PASS;
}

int tcp_handler_send(struct __sk_buff *skb)
{
	__u64 tcp_bytes_sent, tcp_bytes_received;
	struct tcp_send_check_sample_cfg *cfg;
	struct tcpsocketmap_value *socket;
	struct handler_vars *vars;
	struct cfg_value *l3cfg;
	struct tcp_sock *tcp;
	struct sock *sk;
	__u32 rcv_wnd;
	int zero = 0;
	u32 txs = 0;
	__u8 state;
	__u64 c;

	vars = (struct handler_vars *)map_lookup_elem(&tg_p_l3_dsptchr, &zero);
	if (!vars)
		return SK_PASS;

	c = vars->cookie;
	// We can just cast pointers here because a struct bpf_sock * points to the same location
	// as a struct sock * (with BPF magic behind the scenes to provide different functionality).
	tcp = (struct tcp_sock *)c;
	sk = (struct sock *)tcp;
	if (!tcp) {
		emit_ip_error_event(skb, 0, &vars->cookie, false, 4, 2, 0, IP_ERROR_TCP_SEND_NO_TCPSOCK);
		return SK_PASS;
	}

	probe_read_kernel(&state, sizeof(state), _((const void *)&(sk->__sk_common.skc_state)));

	socket = lookup_tcpsocketmap(&c);
	if (unlikely(!socket)) {
		// Don't report an error here if the TCP socket isn't yet active.
		// Sockets can enter TCP_ESTABLISHED before the socket graft happens. We check
		// that we haven't sent a packet or an ACK in that case.
		if (bpf_core_field_exists(tcp->segs_out))
			probe_read_kernel(&txs, sizeof(__u32), _(&(tcp->segs_out)));
		if (tcp_active(state) && txs > 1) {
			emit_ip_error_event(skb, 0, &vars->cookie, false, 4, 2, 0, IP_ERROR_TCP_SEND_NO_SOCKET);
		}
		return SK_PASS;
	}

	probe_read_kernel(&tcp_bytes_sent, sizeof(__u64), _(&(tcp->bytes_sent)));
	probe_read_kernel(&tcp_bytes_received, sizeof(__u64), _(&(tcp->bytes_received)));
	probe_read_kernel(&rcv_wnd, sizeof(__u32), _(&(tcp->rcv_wnd)));

	if (!rcv_wnd && state == TCP_ESTABLISHED)
		socket->stats.zero_window++;

	l3cfg = getl3cfg();
	if (l3cfg) {
		cfg = &l3cfg->tcp;
		if (cfg->watermarksEnable && socket->key.pid != 0) {
			struct socketmap_value process = {
				.key.ktime = socket->key.ktime,
				.key.pid = socket->key.pid,
			};
			struct process_network_watermarks_config c = {
				.avg_window_size_ms =
					cfg->watermarksAvgWindowSize,
				.window_size =
					cfg->watermarksWindowSizeNs,
				.burst_trigger_mult =
					cfg->watermarksBurstTriggerMult,
				.dip_trigger_mult =
					cfg->watermarksDipTriggerMult,
			};

			if (tcp_bytes_sent > socket->stats.bytes_sent) {
				process_network_watermarks(
					skb, &process, IPPROTO_TCP,
					WATERMARKS_KEY_SEND_EGRESS,
					tcp_bytes_sent - socket->stats.bytes_sent,
					&c);
			}
			if (tcp_bytes_received > socket->stats.bytes_received) {
				process_network_watermarks(
					skb, &process, IPPROTO_TCP,
					WATERMARKS_KEY_SEND_INGRESS,
					tcp_bytes_received - socket->stats.bytes_received,
					&c);
			}
		}
	}
	cgrp_tcp_socketmap_stats(sk, socket);
#ifdef PROCESS_TREE
	return process_socketmap_send(socket, skb);
#endif
	return SK_PASS;
}

int tcp_handler_ip4_recv(struct __sk_buff *skb)
{
#ifdef PROCESS_TREE
	struct tcpsocketmap_value *socket;
	struct handler_vars *vars;
	int zero = 0;
	__u64 c;

	vars = (struct handler_vars *)map_lookup_elem(&tg_p_l3_dsptchr, &zero);
	if (!vars)
		return SK_PASS;

	c = vars->cookie;
	socket = lookup_tcpsocketmap(&c);
	if (socket) {
		int verdict = process_socketmap_recv(socket, skb);

		if (verdict == SK_DROP)
			return SK_DROP;
	}
#endif

	return SK_PASS;
}

int tcp_handler_ip4(struct __sk_buff *skb, int send)
{
	if (send) {
		if (CGROUP_PROBE_READ)
			return tcp_handler_send(skb);
		return SK_PASS;
	}

	if (CGROUP_PROBE_READ) {
		void *data_end = (void *)(long)skb->data_end;
		void *data = (long *)(long)skb->data;
		struct handler_vars *vars;
		struct iphdr *ip;
		int zero = 0;

		vars = (struct handler_vars *)map_lookup_elem(&tg_p_l3_dsptchr, &zero);
		if (!vars)
			return SK_PASS;

		if (data + sizeof(struct iphdr) > data_end)
			ip = &vars->ip;
		else
			ip = (struct iphdr *)data;

		tcp_check_fin_rx(skb, ip, ip->ihl * sizeof(__u32), &vars->cookie, false);
	}
	return tcp_handler_ip4_recv(skb);
}
int tcp_handler_ip6(struct __sk_buff *skb, u16 payload_off, int send)
{
	if (CGROUP_PROBE_READ) {
		struct handler_vars *vars;
		struct ipv6hdr *ip6;
		int zero = 0;

		vars = (struct handler_vars *)map_lookup_elem(&tg_p_l3_dsptchr, &zero);
		if (!vars)
			return SK_PASS;
		ip6 = &vars->ip6;

		if (send)
			return tcp_handler_send(skb);

		tcp_check_fin_rx(skb, ip6, payload_off, &vars->cookie, true);
	}
	return SK_PASS;
}

#endif //__BPF_TCP_RECV_H_
