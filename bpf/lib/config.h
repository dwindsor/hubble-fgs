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
struct tcp_send_check_sample_cfg {
	__u8 watermarksEnable;
	__u8 rttEnable;
	__u8 pad[6];
	__u64 watermarksAvgWindowSize;
	__u64 watermarksWindowSizeNs;
	__u64 watermarksBurstTriggerMult;
	__u64 watermarksDipTriggerMult;
	__u32 bucket00;
	__u32 bucket01;
	__u32 bucket10;
	__u32 bucket25;
	__u32 bucket50;
	__u32 bucket75;
	__u32 bucket90;
	__u32 bucket99;
};

struct tcp_event_disable_config {
	__u8 disableConnect;
	__u8 disableClose;
	__u8 disableAccept;
	__u8 disableListen;
	__u32 pad;
};

struct udp_sensor_config {
	u16 dns_ports[4];
	u8 dns_stats_per_socket;
	u8 dns_report_questions;
	u8 watermarks_enable;
	u8 disable_listen_events;
	u8 disable_connect_events;
	u8 disable_close_events;
	u8 pad[2];
	u64 watermarks_avg_window_size_ms;
	u64 watermarks_window_size;
	u64 watermarks_burst_trigger_percent;
	u64 watermarks_dip_trigger_percent;
	u64 seq_check_app_id;
	u16 seq_check_ports[8];
};

struct cgroup_dispatch_cfg {
	uint32_t icmp4;
	uint32_t icmp6;
	uint32_t tcp4;
	uint32_t tcp6;
	uint32_t udp4;
	uint32_t udp6;
};

struct cfg_value {
	__u8 icmp_tracking_enabled;
	__u8 icmp_net_match;
	__u8 raw_enabled;
	__u8 raw_report_close;
	__u8 udp_report_close;
	__u8 icmp_v6_info;
	__u8 pad[2];
	struct tcp_send_check_sample_cfg tcp;
	struct tcp_event_disable_config tcp_disable;
	struct udp_sensor_config udp;
	struct cgroup_dispatch_cfg proto;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct cfg_value);
	__uint(max_entries, 1);
} tg_l3_cfg SEC(".maps");

static inline __attribute__((always_inline)) struct cfg_value *
getl3cfg()
{
	int zero = 0;

	return (struct cfg_value *)map_lookup_elem(&tg_l3_cfg, &zero);
}

#endif
