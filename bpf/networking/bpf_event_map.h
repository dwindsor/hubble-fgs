// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef __BPF_EVENT_MAP_H_
#define __BPF_EVENT_MAP_H_

#include "vmlinux.h"

#include "api.h"
#include "bpf_helpers.h"

// We make this a msg_udp_event as it is bigger than a standard msg_ip_event struct
// and also bigger than the msg_ip_with_tnp_event. This means it can be used for all
// event types.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct msg_udp_event);
	__uint(max_entries, 1);
} tg_h_event SEC(".maps");

#endif
