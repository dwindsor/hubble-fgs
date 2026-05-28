// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef __BPF_UDP_MCAST_H__
#define __BPF_UDP_MCAST_H__

#define SAMPLE_BYTES_TO_HASH 8

#include "vmlinux.h"
#include "lib/bpf_helpers.h"
#include "lib/networkmsg.h"
#include "lib/iso_msg_types.h"
#include "bpf_cookie.h"
#include "bpf_tracing.h"
#include "config.h"
#include "bpf_udp_lseg_mtp.h"
#include "bpf_udp_rtp.h"
#include "jhash.h"

// We include a string here that we don't expect to be found elsewhere in the code base,
// so that we can grep for it and convince ourselves (in CI) that the string here was
// included in the code.
// We then include a second string ("canary:lseg_build") inside the LSEG-specific code
// block, which we can also grep for in CI, to convince ourselves that the LSEG-specific
// code has not been included in a non-LSEG build.
static char base_build_canary[] __attribute__((used)) = "canary:base_build";

static inline __attribute__((always_inline)) bool
match_mcast_check_ports(u16 *ports, uint16_t port)
{
	int i;

#pragma unroll
	for (i = 0; i < 8; i++) {
		if (!ports[i])
			return false;
		if (ports[i] == port)
			return true;
	}
	return false;
}

// check if this is multicast, and if so, if we are observing it
static inline __attribute__((always_inline)) bool
is_udp_mcast_obs(struct udp_sensor_config *config, struct udp_info_key *k)
{
	u8 ip4msb;

	// only IPv4 currently
	if (k->tuple.ipv6)
		return false;

	// check if we are observing multicast
	if (!config->multicast_app_id)
		return false;

	// check the destination is a multicast address 224.0.0.0 - 239.255.255.255
	// and the destination ports match
	ip4msb = k->tuple.daddr[0] & 0xff;
	if (ip4msb >= 224 && ip4msb < 240 && match_mcast_check_ports(config->multicast_ports, k->tuple.dport))
		return true;

	// check the source is a multicast address 224.0.0.0 - 239.255.255.255
	// and the source ports match
	ip4msb = k->tuple.saddr[0] & 0xff;
	if (ip4msb >= 224 && ip4msb < 240 && match_mcast_check_ports(config->multicast_ports, k->tuple.sport))
		return true;

	return false;
}

// We return 0 in the case of errors. We might improve this in time.
static inline __attribute__((always_inline)) u64
udp_mcast_get_conn_id(struct __sk_buff *skb, struct iphdr *ip, bool ipv6,
		      u64 *cookie, int payload_off, int payload_sz, struct socketmap_value *process,
		      struct udp_info_key *k)
{
	struct cfg_value *l3cfg = getl3cfg();
	struct udp_sensor_config *config;

	if (!l3cfg)
		return 0;
	config = &l3cfg->udp;

	if (!is_udp_mcast_obs(config, k))
		return 0;

	switch (config->multicast_app_id) {
#ifdef LSEG
	case MULTICAST_APP_LSEGMTP: {
		u8 line_id_sz, seq_num_sz;
		u64 line_id;

		if (get_lseg_mtp_format(&line_id_sz, &seq_num_sz,
					skb, ip, ipv6, cookie, payload_off, payload_sz) < 0)
			return 0;

		line_id = get_lseg_mtp_line_id(skb, ip, ipv6,
					       cookie, payload_off, payload_sz, line_id_sz);
		return line_id;
	}
#endif
	case MULTICAST_APP_RTP:
		return get_rtp_ssrc(skb, ip, ipv6, cookie, payload_off, payload_sz);
	}
	return 0;
}

static inline __attribute__((always_inline)) void
udp_seq_err_check(struct __sk_buff *skb, struct iphdr *ip, bool ipv6,
		  u64 *cookie, int payload_off, int payload_sz, struct socketmap_value *process,
		  struct udp_info_key *k, struct udp_info_value *v, u64 multicast_app_id)
{
	switch (multicast_app_id) {
#ifdef LSEG
	case MULTICAST_APP_LSEGMTP:
		udp_seq_err_check_mtp(skb, ip, ipv6, cookie,
				      payload_off, payload_sz, process, k, v);
		return;
#endif
	case MULTICAST_APP_RTP:
		udp_seq_err_check_rtp(skb, ip, ipv6, cookie,
				      payload_off, payload_sz, process, k, v);
		return;
	}
}

static inline __attribute__((always_inline)) void
udp_sample_multicast(struct __sk_buff *skb, struct iphdr *ip, bool ipv6,
		     u64 *cookie, int payload_off, int payload_sz, u64 send,
		     struct socketmap_value *process,
		     struct udp_info_key *k, struct udp_info_value *v,
		     u64 multicast_app_id, u32 sample_threshold)
{
	struct msg_ip_event *e;
	int zero = 0;
	u64 data;
	u32 hash;

	switch (multicast_app_id) {
#ifdef LSEG
	case MULTICAST_APP_LSEGMTP:
		data = udp_sample_lseg(skb, payload_off, payload_sz);
		if (!data) {
			emit_ip_error_event(skb, ip, cookie, ipv6,
					    ip->version, send + 1, 0, IP_ERROR_UDP_SAMPLE_READ_PAYLOAD_DATA);
			return;
		}
		break;
#endif
	case MULTICAST_APP_RTP:
		data = udp_sample_rtp(skb, payload_off, payload_sz);
		if (!data) {
			emit_ip_error_event(skb, ip, cookie, ipv6,
					    ip->version, send + 1, 0, IP_ERROR_UDP_SAMPLE_READ_PAYLOAD_DATA);
			return;
		}
		break;
	default:
		return;
	}

	hash = jhash(&data, SAMPLE_BYTES_TO_HASH, 0);

	if (hash > sample_threshold)
		return;

	// Create event.
	e = (struct msg_ip_event *)map_lookup_elem(&tg_h_event, &zero);
	if (!e)
		return;

	e->common.op = ISO_MSG_OP_MULTICAST_SAMPLE;
	e->common.size = sizeof(struct msg_ip_event);
	e->common.ktime = tg_get_ktime();
	if (process) {
		e->key.pid = process->key.pid;
		e->key.ktime = process->key.ktime;
	} else {
		e->key.pid = 0;
		e->key.ktime = 0;
	}
	e->tuple = k->tuple;
	e->socket_cookie = k->cookie;
	e->version = k->version;
	e->ps_version = v->ps_version;
	e->socket_flags = send;
	e->create_time = 0;
	e->close_time = 0;
	// add the 8 bytes that we've hashed for later comparison.
	e->ret = data;
	perf_event_output_metric(skb, ISO_MSG_OP_MULTICAST_SAMPLE, &tcpmon_map, BPF_F_CURRENT_CPU, e, sizeof(struct msg_ip_event));
}

static inline __attribute__((always_inline)) void
udp_check_multicast(struct __sk_buff *skb, struct iphdr *ip, bool ipv6,
		    u64 *cookie, int payload_off, int payload_sz, u64 send,
		    struct socketmap_value *process,
		    struct udp_info_key *k, struct udp_info_value *v)
{
	struct cfg_value *l3cfg = getl3cfg();
	struct udp_sensor_config *config;

	if (!l3cfg)
		return;
	config = &l3cfg->udp;

	if (!is_udp_mcast_obs(config, k))
		return;

	/* Only check sequence numbers on received packets. */
	if (!send && config->enable_multicast_seq_check)
		udp_seq_err_check(skb, ip, ipv6, cookie, payload_off,
				  payload_sz, process, k, v, config->multicast_app_id);
	if (config->multicast_sample_threshold)
		udp_sample_multicast(skb, ip, ipv6, cookie, payload_off,
				     payload_sz, send, process, k, v, config->multicast_app_id,
				     config->multicast_sample_threshold);
}

#endif // __BPF_UDP_MCAST_H__
