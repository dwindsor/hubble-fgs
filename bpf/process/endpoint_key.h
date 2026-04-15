// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef __ENDPOINT_KEY_H__
#define __ENDPOINT_KEY_H__

/* Lightweight subset of process_endpoint.h. Extracted so that
 * bpf_udp_info.h can use destination_endpoint_key without including
 * process_endpoint.h, which transitively pulls in lib/process.h and
 * its BPF atomic operations. Those atomics compile to BPF_ATOMIC
 * instructions (kernel 5.12+) and break kernels 5.4, 5.10, and
 * rhel8.10 when included in every program in the bpf_cookie.h chain.
 * All field types are uint32_t/uint64_t; callers already include vmlinux.h.
 */

struct tree_id {
	uint32_t uid;
	/* cpu stores full 32-bit value; highest bit (TREE_ID_IGNORE_ARGS_BIT) used as ignore_args flag */
	uint32_t cpu;
};

/* Somewhat counter-intuitively destinations are scoped by local
 * id and/or local ns_id. This ensures that if two processes in
 * the same network namespace sending to a destination will have
 * separate stats. Similarly if the same process in different
 * pods will have multiple stat records.
 */
struct destination_endpoint_key {
	struct tree_id local_id;
	uint64_t local_nsid;
	uint64_t destination_id; // unwrapped endpoint_id_value
	uint64_t source;
	uint32_t port;
	uint32_t protocol;
};

#endif /* __ENDPOINT_KEY_H__ */
