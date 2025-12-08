#include "bpf_helpers.h"
#include "ebpf_ntos_hooks.h"
#include "process.h"

#define MSG_OP_EXECVE 5
#define MSG_OP_EXIT   7

struct msg_common {
	uint8_t op;
	uint8_t flags; // internal flags not exported
	uint8_t pad[2];
	uint32_t size;
	uint64_t ktime;
};

// Declare a per-CPU array to be used as scratch space.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, uint64_t); // key is pid_tgid
	__uint(value_size, COMMAND_SCRATCH_SIZE);
	__uint(max_entries, 1);
} tg_h_scratch_space SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, uint64_t); // key is pid_tgid
	__uint(value_size, COMMAND_SCRATCH_SIZE);
	__uint(max_entries, 1024);
} scratch_space SEC(".maps");

// The non variable fields from the process_md_t struct.
// Note: this must be kept in sync with the C# version in process_monitor.Library's ProcessMonitorBPFLoader.cs
struct process_create_info_t {
	struct msg_common common;
	uint32_t process_id;
	uint32_t parent_process_id;
	uint32_t creating_process_id;
	uint32_t creating_thread_id;
	uint64_t user_luid;
	uint64_t creation_time; ///< Process creation time.
};

struct process_exit_info_t {
	struct msg_common common;
	uint32_t process_id;
	uint64_t exit_time; ///< Process exit time.
	uint32_t process_exit_code;
	uint8_t operation;
};

// Ring-buffer for process_info_t.
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} process_ringbuf SEC(".maps");

// The following line is optional, but is used to verify
// that the ProcesMonitor prototype is correct or the compiler
// would complain when the function is actually defined below.
process_hook_t ProcessMonitor;

inline __attribute__((always_inline)) void *
get_scratch_space()
{
	uint64_t current_pid_tgid_key = bpf_get_current_pid_tgid();
	void *scratch = bpf_map_lookup_elem(&tg_h_scratch_space, &current_pid_tgid_key);

	if (!scratch) {
		uint32_t zero_key = 0;
		// Allocate scratch space for this CPU.
		scratch = bpf_map_lookup_elem(&tg_h_scratch_space, &zero_key);

		if (!scratch)
			return NULL;

		// Insert into the LRU map.
		bpf_map_update_elem(&scratch_space, &current_pid_tgid_key, scratch, BPF_ANY);

		// Get the pointer to the scratch space.
		scratch = bpf_map_lookup_elem(&scratch_space, &current_pid_tgid_key);
		if (!scratch)
			return NULL;

		// Initialize the scratch space.
		memset(scratch, 0, COMMAND_SCRATCH_SIZE);
	}
	return scratch;
}

inline __attribute__((always_inline)) void str_to_lower_and_copy(void *dst, void *src, int len)
{
	char *d = (char *)dst;
	char *s = (char *)src;

	for (int i = 0; (i < len); i++) {
		char p = s[i];

		if (p >= 'A' && p <= 'Z')
			p += 0x20;
		d[i] = p;
	}
}

inline __attribute__((always_inline)) void str_to_lower(void *src, int len)
{
	char *s = (char *)src;

	for (int i = 0; (i < len); i++) {
		char p = s[i];

		if (p >= 'A' && p <= 'Z')
			p += 0x20;
		s[i] = p;
	}
}

SEC("process")
int ProcessMonitor(process_md_t *ctx)
{
	if (ctx->operation == PROCESS_OPERATION_CREATE) {
		struct process_create_info_t process_create_info;

		int size = sizeof(process_create_info);
		int wchar_size = 0;

		memset(&process_create_info, 0, size);
		process_create_info.common.op = MSG_OP_EXECVE;
		process_create_info.common.size = size;
		process_create_info.common.ktime = ctx->creation_time;
		process_create_info.process_id = ctx->process_id;
		process_create_info.parent_process_id = ctx->parent_process_id;
		process_create_info.creating_process_id = ctx->creating_process_id;
		process_create_info.creating_thread_id = ctx->creating_thread_id;
		process_create_info.user_luid = bpf_get_current_logon_id(ctx);
		process_create_info.creation_time = ctx->creation_time;

		void *buffer = get_scratch_space();
		void *image_path_buf = buffer + IMAGE_PATH_OFFSET;

		if (!buffer)
			return 0;

		int command_length = ctx->command_end - ctx->command_start;

		if (command_length > (COMMAND_SCRATCH_SIZE - IMAGE_PATH_OFFSET - 1))
			command_length = (COMMAND_SCRATCH_SIZE - IMAGE_PATH_OFFSET - 1);

		str_to_lower_and_copy(buffer, ctx->command_start, command_length);

		bpf_map_update_elem(&command_map, &process_create_info.process_id, buffer, BPF_ANY);

		// Reset the buffer.
		memset(image_path_buf, 0, IMAGE_PATH_SIZE);

		// Copy image path into the LRU hash.  Note we use IMAGE_PATH_SIZE - 1 to leave a guaranteed null terminator
		int path_len = bpf_process_get_image_path(ctx, image_path_buf, IMAGE_PATH_SIZE - 1);

		if (path_len > IMAGE_PATH_SIZE - 1)
			path_len = IMAGE_PATH_SIZE - 1;
		str_to_lower(image_path_buf, path_len);
		bpf_map_update_elem(&process_map, &process_create_info.process_id, image_path_buf, BPF_ANY);
		update_binary_uid_map(process_create_info.process_id, image_path_buf, buffer);
		bpf_ringbuf_output(&process_ringbuf, &process_create_info, sizeof(process_create_info), 0);

	} else if (ctx->operation == PROCESS_OPERATION_DELETE) {
		struct process_exit_info_t process_exit_info;
		int size = sizeof(process_exit_info);
		uint32_t *pid = NULL;

		if ((ctx) && ctx->process_id)
			*pid = ctx->process_id;
		else
			return 0;

		memset(&process_exit_info, 0, size);
		process_exit_info.process_id = *pid;
		process_exit_info.common.op = MSG_OP_EXIT;
		process_exit_info.common.ktime = ctx->exit_time;
		process_exit_info.common.size = size;
		process_exit_info.exit_time = ctx->exit_time;
		process_exit_info.process_exit_code = ctx->process_exit_code;
		bpf_map_delete_elem(&process_map, pid);
		bpf_map_delete_elem(&command_map, pid);
		bpf_ringbuf_output(&process_ringbuf, &process_exit_info, sizeof(process_exit_info), 0);
	}
	return 0;
}
