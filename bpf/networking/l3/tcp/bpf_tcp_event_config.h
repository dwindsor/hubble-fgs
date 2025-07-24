// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef __BPF_TCP_NETWORK_EVENT_CONFIG_H__
#define __BPF_TCP_NETWORK_EVENT_CONFIG_H__

#include "vmlinux.h"
#include "api.h"
#include "../lib/bpf_helpers.h"

struct event_disable_config {
	__u8 disableConnect;
	__u8 disableClose;
	__u8 disableAccept;
	__u8 disableListen;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct event_disable_config);
	__uint(max_entries, 1);
} tg_l3_tcp_dsble SEC(".maps");

#endif
