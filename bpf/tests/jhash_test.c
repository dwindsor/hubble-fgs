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
#include "bpf_tracing.h"
#include "bpf_helpers.h"

#include "jhash.h"

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";

struct jhash_test {
	u8 input[16];
	u32 output;
	u32 len;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct jhash_test);
	__uint(max_entries, 1);
} tg_jhash_test SEC(".maps");

__attribute__((section("raw_tracepoint/test"), used)) int test_jhash(unsigned long long *ctx)
{
	struct jhash_test *test;
	u32 zero = 0;

	test = map_lookup_elem(&tg_jhash_test, &zero);
	if (!test)
		return 0;

	test->output = jhash(&test->input, test->len & 0xf, 0);

	return 0;
}
