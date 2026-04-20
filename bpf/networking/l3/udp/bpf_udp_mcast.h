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

#include "vmlinux.h"
#include "lib/bpf_helpers.h"
#include "lib/networkmsg.h"
#include "lib/iso_msg_types.h"
#include "bpf_cookie.h"
#include "bpf_tracing.h"
#include "config.h"
#include "bpf_udp_lseg_mtp.h"
#include "bpf_udp_rtp.h"

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
		  struct udp_info_key *k, struct udp_info_value *v)
{
	struct cfg_value *l3cfg = getl3cfg();
	struct udp_sensor_config *config;

	if (!l3cfg)
		return;
	config = &l3cfg->udp;

	if (!config->enable_multicast_seq_check)
		return;

	if (!is_udp_mcast_obs(config, k))
		return;

	switch (config->multicast_app_id) {
#ifdef LSEG
	case MULTICAST_APP_LSEGMTP:
		udp_seq_err_check_mtp(skb, ip, ipv6, cookie,
				      payload_off, payload_sz, process, k);
		return;
#endif
	case MULTICAST_APP_RTP:
		udp_seq_err_check_rtp(skb, ip, ipv6, cookie,
				      payload_off, payload_sz, process, k, v);
		return;
	}
}

#endif // __BPF_UDP_MCAST_H__
