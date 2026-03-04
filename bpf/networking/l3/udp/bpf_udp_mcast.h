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

// We include a string here that we don't expect to be found elsewhere in the code base,
// so that we can grep for it and convince ourselves (in CI) that the string here was
// included in the code.
// We then include a second string ("canary:lseg_build") inside the LSEG-specific code
// block, which we can also grep for in CI, to convince ourselves that the LSEG-specific
// code has not been included in a non-LSEG build.
static char base_build_canary[] __attribute__((used)) = "canary:base_build";

static inline __attribute__((always_inline)) bool
match_seq_check_ports(u16 *ports, uint16_t port1, uint16_t port2)
{
	int i;

#pragma unroll
	for (i = 0; i < 8; i++) {
		if (!ports[i])
			return false;
		if (ports[i] == port1 || ports[i] == port2)
			return true;
	}
	return false;
}

static inline __attribute__((always_inline)) void
udp_seq_err_check(struct __sk_buff *skb, void *skb_head, struct iphdr *ip, bool ipv6,
		  u64 *cookie, int payload_off, int payload_sz, struct socketmap_value *process,
		  struct udp_info_key *k, struct udp_info_value *v)
{
#ifndef IS_KPROBE
	struct cfg_value *l3cfg = getl3cfg();
	struct udp_sensor_config *config;

	if (!l3cfg)
		return;
	config = &l3cfg->udp;

	if (!config->enable_multicast_seq_check || !config->multicast_app_id)
		return;

	if (!match_seq_check_ports(config->multicast_ports, k->tuple.sport, k->tuple.dport))
		return;

	switch (config->multicast_app_id) {
#ifdef LSEG
	case MULTICAST_APP_LSEGMTP:
		udp_seq_err_check_mtp(skb, skb_head, ip, ipv6, cookie,
				      payload_off, payload_sz, process, k, v, config);
		return;
#endif
	}
#endif
}

#endif // __BPF_UDP_MCAST_H__
