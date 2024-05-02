// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef __BPF_FD_LOOKUP_H_
#define __BPF_FD_LOOKUP_H_

#include "vmlinux.h"
#include "bpf_event.h"
#include "bpf_cookie.h"
#include "bpf_fd_to_sk.h"
#include "../lib/address_family.h"
#include "bpf_tracing.h"
#include "bpf_network_helpers.h"

#define S_IFMT	 00170000
#define S_IFSOCK 0140000

struct fd_lookup_config {
	uint32_t pid;
	uint32_t fd;
	uint64_t sockaddr;
	uint64_t saddr[2];
	uint64_t daddr[2];
	uint16_t sport;
	uint16_t dport;
	uint16_t protocol;
	uint8_t state;
	uint8_t ipv6;
	uint8_t signal_hit;
	uint8_t pad1;
	uint16_t family;
	uint16_t pad2;
	uint16_t pad3;
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct fd_lookup_config);
	__uint(max_entries, 1);
} fd_lookup_config_map SEC(".maps");

static inline __attribute__((always_inline)) struct execve_map_value *
event_find_task(struct task_struct *task, __u32 pid, __u32 *ppid, bool *walked)
{
	struct execve_map_value *value = 0;
	int i;

#pragma unroll
	for (i = 0; i < 4; i++) {
		value = execve_map_get_noinit(pid);
		if (value && value->key.ktime != 0)
			break;
		value = 0;
		*walked = 1;
		probe_read_kernel(&task, sizeof(task), _(&task->parent));
		if (!task)
			break;
		probe_read_kernel(&pid, sizeof(pid), _(&task->tgid));
	}
	*ppid = pid;
	return value;
}

static inline __attribute__((always_inline)) int
__kprobe_proc_task_name(struct pt_regs *ctx)
{
	struct task_struct *p = (struct task_struct *)PT_REGS_PARM2(ctx);
	struct socketmap_value sockmap_process = { 0 };
	struct tcpsocketmap_value tcp_stats = { 0 };
	struct fd_lookup_config *config;
	struct execve_map_value *value;
	u16 required_protocol;
	bool read_ok = false;
	struct sock *sk;
	u16 family = 0;
	int sk_err = 0;
	int zero = 0;
	uint32_t pid;
	bool walked;
	u64 cookie;
	u32 ppid;

	config = (struct fd_lookup_config *)map_lookup_elem(
		&fd_lookup_config_map, &zero);
	if (!config)
		return 0;
	config->signal_hit = 1;

	/* The config specifies the protocol to care about */
	required_protocol = config->protocol;

	/* Clear the protocol in the config to indicate the socket doesn't
	 * match. This will be completed later if a valid socket matches.
	 */
	config->protocol = 0;

	if (probe_read_kernel(&pid, sizeof(pid), _(&(p->tgid))) < 0)
		return 0;
	if (config->pid != pid)
		return 0;

	/* If the socket address (pseudo cookie) has been provided, then we don't need to look up,
	 * we just need to store it. */
	if (!config->sockaddr) {
		sk_err = fd_to_sk(&sk, p, config->fd, required_protocol, &read_ok, &family);
		switch (sk_err) {
		case FD_TO_SK_SUCCESS:
			break;
		case FD_TO_SK_INVALID_PTRS:
			/* This should never happen. Mark it as an error. */
			config->protocol = -1;
			return 0;
		case FD_TO_SK_READ_ERROR_OTHER:
		case FD_TO_SK_READ_ERROR_FILE:
		case FD_TO_SK_READ_ERROR_INODE: {
			u64 reason = sk_err;
			emit_ip_error_event(ctx, 0, &reason, 0, 0, 0, 0, IP_ERROR_SOCKET_DISCOVERY_READ_ERROR);
			/* Mark this as an error. */
			config->protocol = -1;
			return 0;
		}
		case FD_TO_SK_WRONG_FAMILY:
		case FD_TO_SK_WRONG_PROTO:
			/* An incorrect family or protocol does not mean a failure, but just
			 * that the socket didn't meet our expectations. Leave protocol as 0.
			 */
			return 0;
		case FD_TO_SK_NO_SK:
			/* Mark this as an error. */
			config->protocol = -1;
			emit_ip_error_event(ctx, 0, 0, 0, 0, 0, 0, IP_ERROR_SOCKET_DISCOVERY_NO_SK);
			return 0;
		}
		if (!sk) {
			/* Mark this an an error. */
			config->protocol = -1;
			emit_ip_error_event(ctx, 0, 0, 0, 0, 0, 0, IP_ERROR_SOCKET_DISCOVERY_NO_SK);
			return 0;
		}
	} else {
		sk = (struct sock *)config->sockaddr;
		read_ok = 1;
		family = config->family;
	}

	cookie = (u64)sk;

	value = event_find_task(p, pid, &ppid, &walked);
	if (!value) {
		emit_ip_error_event(ctx, 0, &cookie, 0,
				    0, 0, 0, IP_ERROR_SOCKET_DISCOVERY_NO_PROCESS);
		/* This isn't a look up error, but a missing process error,
		 * so let userspace worry about this.
		 */
		config->protocol = -1;
		return 0;
	}

	/* If we can't read the address family or protocol, then we can't
	 * report the socket.
	 */
	if (!read_ok) {
		/* This is a read error, so let userspace work it out. */
		config->protocol = -1;
		return 0;
	}

	/* Pass the details of the socket back via the config map so that an 
	 * appropriate event can be generated. We don't use the usual ring
	 * buffer here because this preceeds the event handlers being
	 * established.
	 */
	probe_read_kernel(&config->sport, sizeof(config->sport),
			  _(&(sk->__sk_common.skc_num)));
	probe_read_kernel(&config->dport, sizeof(config->dport),
			  _(&(sk->__sk_common.skc_dport)));
	config->dport = bpf_ntohs(config->dport);
	probe_read_kernel(&config->state, sizeof(config->state),
			  (const void *)_(&(sk->__sk_common.skc_state)));
	config->protocol = required_protocol;
	config->sockaddr = cookie;
	if (family == AF_INET) {
		config->ipv6 = 0;
		config->saddr[0] = 0;
		config->saddr[1] = 0;
		config->saddr[0] = 0;
		config->saddr[1] = 0;
		probe_read_kernel(&config->saddr[0], sizeof(uint32_t),
				  _(&(sk->__sk_common.skc_rcv_saddr)));
		probe_read_kernel(&config->daddr[0], sizeof(uint32_t),
				  _(&(sk->__sk_common.skc_daddr)));
	} else {
		config->ipv6 = 1;
		probe_read_kernel(config->saddr, sizeof(config->saddr),
				  _(&(sk->__sk_common.skc_v6_rcv_saddr)));
		probe_read_kernel(config->daddr, sizeof(config->daddr),
				  _(&(sk->__sk_common.skc_v6_daddr)));
	}

	sockmap_process.key.pid = value->key.pid;
	sockmap_process.key.ktime = value->key.ktime;
	// Store the create time as the current time (e.g. Tetragon start up time).
	// This is far from perfect, but at least the discovered flag will indicate
	// how we found this create time in case we want to exclude these.
	sockmap_process.create_time = ktime_get_ns();
	sockmap_process.protocol = required_protocol;

	if (required_protocol == IPPROTO_UDP)
		sockmap_process.version = udp_cookie_inc_version();
	else
		sockmap_process.version = 0;

	/* Store the socket even if family or protocol couldn't be read. */
	add_socketmap(&cookie, &sockmap_process, true);

	if (required_protocol == IPPROTO_TCP) {
		tcp_socketmap_stats(sk, &tcp_stats);
		tcp_stats.key = value->key;
		add_tcpsocketmap(&cookie, &tcp_stats, false);
	}

	return 0;
}

#endif