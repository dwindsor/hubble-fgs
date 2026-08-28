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

#define BPF_AREA_DNS  1 << 0
#define BPF_AREA_HTTP 1 << 1
#define BPF_AREA_TCP  1 << 2

// Code below is same as OSS one from lib/common.h but we read from FGS_CONFIG macro
#include <bpf_tracing.h>
#include "fgs_rodata_config.h"

// If TETRAGON_BPF_DEBUG is set, always enable debug messages
#ifdef TETRAGON_BPF_DEBUG
#define FGS_DEBUG_AREA DEBUG_AREA
#else
// Use the proper FGS_CONFIG value to check whether debug messages are enabled
#define FGS_DEBUG_AREA(area, __fmt, ...)            \
	if (FGS_CONFIG(BPF_DEBUG_ENABLED) & (area)) \
		bpf_printk("tetragon@" #area " | " __fmt, ##__VA_ARGS__);
#endif
