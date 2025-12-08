// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef __PROCESS_H__
#define __PROCESS_H__

#define IMAGE_PATH_SIZE (1024)

// 64k bytes is the max byte count that fits in a UNICODE_STRING
// (because Length is a USHORT).  Exactly 64k seems to be a little too high
// for eBPF, so we subtract a few bytes and the likelihood this actually
// truncates anything important is pretty low.
#define COMMAND_SCRATCH_SIZE ((64 * 1024) - 16)

#define IMAGE_PATH_OFFSET (COMMAND_SCRATCH_SIZE - IMAGE_PATH_SIZE - 4)

// LRU hash for storing the image path of a process.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, uint32_t); // key is the process id.
	__type(value, char[IMAGE_PATH_SIZE]);
	__uint(max_entries, 1024 * 64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} process_map SEC(".maps");

// LRU hash for storing the command line of a process.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, uint32_t); // key is the process id.
	__type(value, char[COMMAND_SCRATCH_SIZE]);
	__uint(max_entries, 1024 * 64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} command_map SEC(".maps");

struct process_tree_binary_uid_key {
	char binary[IMAGE_PATH_SIZE];
	char command_line[IMAGE_PATH_SIZE];
};

struct tree_id {
	uint32_t uid;
	uint32_t cpu;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, struct process_tree_binary_uid_key);
	__type(value, struct tree_id);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} process_tree_binary_uid_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__uint(key_size, sizeof(struct tree_id));
	__uint(value_size, sizeof(struct process_tree_binary_uid_key));
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} process_tree_uid_binary_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(uint32_t));
	__uint(value_size, sizeof(uint64_t));
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} tg_tree_id SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, uint32_t);
	__type(value, struct process_tree_binary_uid_key);
} tg_h_ps_buidkey SEC(".maps");

inline __attribute__((always_inline)) void get_tree_id(struct tree_id *id)
{
	uint32_t zero = 0;
	uint64_t *counter;

	counter = bpf_map_lookup_elem(&tg_tree_id, &zero);
	if (!counter) {
		id->uid = 0;
		return;
	}

	id->uid = ++(*counter);
	id->cpu = bpf_get_smp_processor_id();
}

inline __attribute__((always_inline)) void update_binary_uid_map(uint32_t pid, char *image_path, char *cmd_line)
{
	struct process_tree_binary_uid_key *tree_key;
	struct tree_id *self_uid, new_uid = { 0 };
	int zero = 0;

	tree_key = bpf_map_lookup_elem(&tg_h_ps_buidkey, &zero);
	if (!tree_key)
		return;
	memset(tree_key, 0, sizeof(*tree_key));
	memcpy_s(tree_key->binary, IMAGE_PATH_SIZE, image_path, IMAGE_PATH_SIZE);

	self_uid = bpf_map_lookup_elem(&process_tree_binary_uid_map, tree_key);
	if (!self_uid) {
		memcpy_s(tree_key->command_line, IMAGE_PATH_SIZE, cmd_line, IMAGE_PATH_SIZE);
		self_uid = bpf_map_lookup_elem(&process_tree_binary_uid_map, tree_key);

		if (!self_uid) {
			self_uid = &new_uid;
			get_tree_id(self_uid);
			if (!self_uid->uid)
				return;
			bpf_map_update_elem(&process_tree_binary_uid_map, tree_key, self_uid, 0);
			bpf_map_update_elem(&process_tree_uid_binary_map, self_uid, tree_key, 0);
		}
	}
}

inline __attribute__((always_inline)) uint64_t find_myself_by_path(uint32_t pid, char *buffer)
{
	struct process_tree_binary_uid_key *tree_key;
	struct tree_id *self_uid, new_uid = { 0 };
	int zero = 0;

	tree_key = bpf_map_lookup_elem(&tg_h_ps_buidkey, &zero);
	if (!tree_key)
		return 0;
	memset(tree_key, 0, sizeof(*tree_key));
	memcpy_s(tree_key->binary, IMAGE_PATH_SIZE, buffer, IMAGE_PATH_SIZE);

	self_uid = bpf_map_lookup_elem(&process_tree_binary_uid_map, tree_key);
	if (!self_uid) {
		void *command_line;

		command_line = bpf_map_lookup_elem(&command_map, &pid);
		if (!command_line)
			return 0;
		memcpy_s(tree_key->command_line, IMAGE_PATH_SIZE, command_line, IMAGE_PATH_SIZE);
		self_uid = bpf_map_lookup_elem(&process_tree_binary_uid_map, tree_key);

		if (!self_uid) {
			self_uid = &new_uid;
			get_tree_id(self_uid);
			if (!self_uid->uid)
				return 0;
			bpf_map_update_elem(&process_tree_binary_uid_map, tree_key, self_uid, 0);
			bpf_map_update_elem(&process_tree_uid_binary_map, self_uid, tree_key, 0);
		}
	}
	return ((uint64_t)self_uid->cpu << 32) | (uint64_t)self_uid->uid;
}

inline __attribute__((always_inline)) uint64_t find_myself_by_id(uint32_t pid)
{
	struct process_tree_binary_uid_key *tree_key;
	struct tree_id *self_uid;

	char *image_path = bpf_map_lookup_elem(&process_map, &pid);

	if (!image_path)
		return 0;

	return find_myself_by_path(pid, image_path);
}
#endif
