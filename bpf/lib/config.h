// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef _CONFIG__
#define _CONFIG__

#include "vmlinux.h"
#include "bpf_helpers.h"

// __CONST is conditionally defined to avoid failing on old kernels with
// "failed: map .rodata: map create: read- and write-only maps not supported
// (requires >= v5.2)"
#ifndef IS_KPROBE
#define __CONST const
#else
#define __CONST
#endif

struct cfg_value {
	__u8 icmp_tracking_enabled;
	__u8 icmp_net_match;
	__u8 raw_enabled;
	__u8 raw_report_close;
	__u8 udp_report_close;
	__u8 enable_bpf_dns_parser;
	__u8 pad[2];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct cfg_value);
	__uint(max_entries, 1);
} tg_l3_cfg SEC(".maps");

#endif
