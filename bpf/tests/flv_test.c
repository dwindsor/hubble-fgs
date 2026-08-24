// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#include "vmlinux.h"
#include "api.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"

#include "tlsmsg.h"

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";

struct flv_zero_test {
	__u32 keep;
	__u8 value[64];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct flv_zero_test);
	__uint(max_entries, 1);
} tg_flv_zero_test SEC(".maps");

__attribute__((section("raw_tracepoint/test"), used)) int test_flv_zero(unsigned long long *ctx)
{
	struct flv_zero_test *test;
	u32 zero = 0;

	test = map_lookup_elem(&tg_flv_zero_test, &zero);
	if (!test)
		return 0;

	flv_zero_tail64(test->value, test->keep);

	return 0;
}
