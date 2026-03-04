// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef __BPF_UDP_SEQ_ERROR_EVENT_H__
#define __BPF_UDP_SEQ_ERROR_EVENT_H__

#include "vmlinux.h"
#include "lib/bpf_helpers.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct msg_udp_seq_error_event);
	__uint(max_entries, 1);
} tg_h_udpseq_ev SEC(".maps");

#endif // __BPF_UDP_SEQ_ERROR_EVENT_H__
