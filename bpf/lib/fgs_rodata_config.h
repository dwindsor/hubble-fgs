// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#pragma once

#include "config.h"

/*
 * FGS_CONFIG() relies on the verifier reading a frozen map's known
 * value to prune the dead branch - support for that only landed in
 * kernel v5.5 ("bpf: Track contents of read-only maps as scalars",
 * a23740ec43ba), so this pre-5.11 tier can't assume it's present.
 *
 * Note the IS_KPROBE is the current gate for __CONST beeeing const,
 * but on kernels without above fix even const const value will not
 * eliminate dead branch.
 */

#ifndef IS_KPROBE

// Independent frozen rodata config map
// unrelated to OSS's own rodata_config map, for enterprise-only feature flags.
struct fgs_rodata_config {
	__u8 DNS_PARSER_PER_POD_ENABLED;
	__u8 TG_MULTICAST_INSPECTION;
	__u8 CGROUP_PROBE_READ;
	__u8 DNS_PARSER_ENABLED;
	__u16 TG_IGMPV3_MAX_EVENT_FRAGS;
	__u8 pad[2];
};

volatile const struct fgs_rodata_config fgs_rodata_config
	__attribute__((section(".rodata.fgs_config"), used));

#define FGS_CONFIG(name) __CONFIG_FIELD(fgs_rodata_config, struct fgs_rodata_config, name)

#else

#define FGS_CONFIG(name) 0

#endif /* IS_KPROBE */
