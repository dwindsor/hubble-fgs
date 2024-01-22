#include "bpf_file.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

struct io_ring_ctx___post58 {
	struct mm_struct *mm_account;
} __attribute__((preserve_access_index));

struct io_ring_ctx___pre58 {
	struct mm_struct *sqo_mm;
} __attribute__((preserve_access_index));

// We get a pointer to the mm_struct from io_ring_ctx in order to assign process context in
// io_uring operations that are issued from kernel threads. This mm_struct is mainly used for
// accounting purposes, but this also serves out purpose.
//
// This function gets the pointer to mm_struct for different kernel versions.
static inline __attribute__((always_inline)) struct mm_struct *get_mm_struct(struct io_ring_ctx *arg)
{
	if (bpf_core_field_exists(arg->sqo_mm)) {
		struct io_ring_ctx___pre58 *ctx = (struct io_ring_ctx___pre58 *)arg;
		struct mm_struct *mm;

		probe_read(&mm, sizeof(mm), _(&ctx->sqo_mm));
		return mm;
	} else {
		struct io_ring_ctx___post58 *ctx = (struct io_ring_ctx___post58 *)arg;
		struct mm_struct *mm;

		probe_read(&mm, sizeof(mm), _(&ctx->mm_account));
		return mm;
	}
}

static inline __attribute__((always_inline)) struct task_struct *io_uring_get_task(struct io_kiocb *req)
{
	struct io_ring_ctx *io_ctx;
	struct mm_struct *mm;
	struct task_struct *task;

	probe_read(&io_ctx, sizeof(io_ctx), _(&req->ctx));
	if (!io_ctx)
		return 0;

	mm = get_mm_struct(io_ctx);
	if (!mm)
		return 0;

	probe_read(&task, sizeof(task), _(&mm->owner));
	return task;
}

// We keep a pointer to the corresponding task_struct inside io_uring_map map.
// The key is the file pointer and the result of get_current_pid_tgid. The value is
// the pointer to task_struct. This function creates that map entry.
static inline __attribute__((always_inline)) int handle_entry(struct io_kiocb *req)
{
	struct io_uring_op_key key;
	struct io_uring_op_val val;
	struct file *file;
	struct task_struct *task;

	task = io_uring_get_task(req);
	if (!task)
		return -FILE_ERR_IOURING_TASK;

	probe_read(&file, sizeof(file), _(&req->file));

	key.file_ptr = (__u64)file;
	key.pid_tgid = get_current_pid_tgid();
	val.user_task = task;

	if (map_update_elem(&io_uring_map, &key, &val, 0) < 0)
		return -FILE_ERR_UPDATE_IOURING_MAP;

	return 0;
}

// This function removed the corresponding entry from io_uring_map.
static inline __attribute__((always_inline)) int handle_exit(struct io_kiocb *req)
{
	struct io_uring_op_key key;
	struct file *file;

	if (!req)
		return 0; // the reason for that is already reported in handle_kretprobe()

	probe_read(&file, sizeof(file), _(&req->file));
	key.file_ptr = (__u64)file;
	key.pid_tgid = get_current_pid_tgid();

	if (map_delete_elem(&io_uring_map, &key) < 0)
		return -FILE_ERR_DELETE_IOURING_MAP;
	return 0;
}

// io_uring_retprobe_map is used to pass function arguments to the kretprobe.
// This function adds an entry to that map.
static inline __attribute__((always_inline)) int handle_kprobe(struct pt_regs *ctx, struct io_kiocb *req)
{
	struct file_retprobe_key key = {
		.pid_tgid = get_current_pid_tgid(),
		.reg = PT_REGS_FP_CORE(ctx),
		.flags = 0,
	};
	struct io_uring_info val = {
		.req = req,
	};

	if (map_update_elem(&io_uring_retprobe_map, &key, &val, 0) < 0)
		return -FILE_ERR_UPDATE_IOURING_RETPROBE_MAP;
	return 0;
}

// This function gets the function arguments from io_uring_retprobe_map and cleanup
// that entry.
static inline __attribute__((always_inline)) struct io_kiocb *handle_kretprobe(struct pt_regs *ctx, int *err)
{
	struct file_retprobe_key key = {
		.pid_tgid = get_current_pid_tgid(),
		.reg = PT_REGS_FP_CORE(ctx),
		.flags = 0,
	};
	struct io_uring_info *val;
	struct io_kiocb *req = 0;

	val = map_lookup_elem(&io_uring_retprobe_map, &key);
	if (!val) {
		*err = -FILE_ERR_LOOKUP_IOURING_RETPROBE_MAP;
		return 0;
	}
	req = val->req;
	if (map_delete_elem(&io_uring_retprobe_map, &key) < 0) {
		*err = -FILE_ERR_DELETE_IOURING_RETPROBE_MAP;
		return 0;
	}
	return req;
}

struct sqe_submit {
	const struct io_uring_sqe *sqe;
	unsigned short index;
	bool has_user;
	bool needs_lock;
	bool needs_fixed_file;
};

struct io_comp_state {
	unsigned int nr;
	struct list_head list;
	struct io_ring_ctx *ctx;
};

static inline __attribute__((always_inline)) void handle_io_readwrite(struct pt_regs *ctx, struct io_kiocb *req, __u32 hook)
{
	int err;

	err = handle_kprobe(ctx, req);
	if (err < 0)
		goto handle_io_readwrite_error;

	err = handle_entry(req);
	if (err < 0)
		goto handle_io_readwrite_error;

	return;

handle_io_readwrite_error:
	inc_error(hook, -err);
}

// io_uring handles all read operations inside io_read function. The call of security_file_permission
// (the hook that we use to monitor read operations) happens inside io_read function. In order to get
// the proper process context we hook at the entry and exit of io_read. As the function prototype of
// io_read has changed a lot during the evolution of io_uring we have a separate hook for each different
// version. These are in the form of kprobe/io_read/XX (i.e. kprobe/io_read/51 provides the function
// prototype for kernel 5.1+). io_uring introduced in kernel 5.1. It seems that the prototype
// of io_read has not further changed since 5.10.

// int io_read(struct io_kiocb *req, const struct sqe_submit *s, bool force_nonblock)
// 5.1 <= KERNEL_VERSION < 5.5
SEC("kprobe/io_read/51")
int BPF_KPROBE(io_read_entry_51, struct io_kiocb *req, const struct sqe_submit *s, bool force_nonblock)
{
	handle_io_readwrite(ctx, req, hook_io_read);
	return 0;
}

// int io_read(struct io_kiocb *req, struct io_kiocb **nxt, bool force_nonblock)
// 5.5 <= KERNEL_VERSION < 5.7
SEC("kprobe/io_read/55")
int BPF_KPROBE(io_read_entry_55, struct io_kiocb *req, struct io_kiocb **nxt, bool force_nonblock)
{
	handle_io_readwrite(ctx, req, hook_io_read);
	return 0;
}

// int io_read(struct io_kiocb *req, bool force_nonblock)
// 5.7 <= KERNEL_VERSION < 5.9
SEC("kprobe/io_read/57")
int BPF_KPROBE(io_read_entry_57, struct io_kiocb *req, bool force_nonblock)
{
	handle_io_readwrite(ctx, req, hook_io_read);
	return 0;
}

// int io_read(struct io_kiocb *req, bool force_nonblock, struct io_comp_state *cs)
// 5.9 <= KERNEL_VERSION < 5.10
SEC("kprobe/io_read/59")
int BPF_KPROBE(io_read_entry_59, struct io_kiocb *req, bool force_nonblock, struct io_comp_state *cs)
{
	handle_io_readwrite(ctx, req, hook_io_read);
	return 0;
}

// int io_read(struct io_kiocb *req, unsigned int issue_flags)
// KERNEL_VERSION >= 5.10
SEC("kprobe/io_read/510")
int BPF_KPROBE(io_read_entry_510, struct io_kiocb *req, unsigned int issue_flags)
{
	handle_io_readwrite(ctx, req, hook_io_read);
	return 0;
}

// We use a single io_read kretprobe for all kernel versions. This is mainly used for cleanup puproses.
SEC("kretprobe/io_read")
int BPF_KRETPROBE(io_read_exit, long ret)
{
	struct io_kiocb *req;
	int err = 0;

	req = handle_kretprobe(ctx, &err);
	if (err < 0)
		goto io_read_exit_error;

	err = handle_exit(req);
	if (err < 0)
		goto io_read_exit_error;

	return 0;

io_read_exit_error:
	inc_error(hook_io_read, -err);
	return 0;
}

// io_uring handles all write operations inside io_write function in a similar way to io_read.

// int io_write(struct io_kiocb *req, const struct sqe_submit *s, bool force_nonblock)
// 5.1 <= KERNEL_VERSION < 5.5
SEC("kprobe/io_write/51")
int BPF_KPROBE(io_write_entry_51, struct io_kiocb *req, const struct sqe_submit *s, bool force_nonblock)
{
	handle_io_readwrite(ctx, req, hook_io_write);
	return 0;
}

// int io_write(struct io_kiocb *req, struct io_kiocb **nxt, bool force_nonblock)
// 5.5 <= KERNEL_VERSION < 5.7
SEC("kprobe/io_write/55")
int BPF_KPROBE(io_write_entry_55, struct io_kiocb *req, struct io_kiocb **nxt, bool force_nonblock)
{
	handle_io_readwrite(ctx, req, hook_io_write);
	return 0;
}

// int io_write(struct io_kiocb *req, bool force_nonblock, struct io_comp_state *cs)
// 5.9 <= KERNEL_VERSION < 5.10
SEC("kprobe/io_write/57")
int BPF_KPROBE(io_write_entry_57, struct io_kiocb *req, bool force_nonblock)
{
	handle_io_readwrite(ctx, req, hook_io_write);
	return 0;
}

// int io_write(struct io_kiocb *req, bool force_nonblock, struct io_comp_state *cs)
// 5.9 <= KERNEL_VERSION < 5.10
SEC("kprobe/io_write/59")
int BPF_KPROBE(io_write_entry_59, struct io_kiocb *req, bool force_nonblock, struct io_comp_state *cs)
{
	handle_io_readwrite(ctx, req, hook_io_write);
	return 0;
}

// int io_write(struct io_kiocb *req, unsigned int issue_flags)
// KERNEL_VERSION >= 5.10
SEC("kprobe/io_write/510")
int BPF_KPROBE(io_write_entry_510, struct io_kiocb *req, unsigned int issue_flags)
{
	handle_io_readwrite(ctx, req, hook_io_write);
	return 0;
}

// We use a single io_write kretprobe for all kernel versions. This is mainly used for cleanup puproses.
SEC("kretprobe/io_write")
int BPF_KRETPROBE(io_write_exit, long ret)
{
	struct io_kiocb *req;
	int err = 0;

	req = handle_kretprobe(ctx, &err);
	if (err < 0)
		goto io_write_exit_error;

	err = handle_exit(req);
	if (err < 0)
		goto io_write_exit_error;

	return 0;

io_write_exit_error:
	inc_error(hook_io_read, -err);
	return 0;
}

// There are cases where the io_read and/or io_write functions are inlined. For this reason we cannot
// hook into those functions. We have seen that only in GKE 5.10 kernel so far, but this is enough to
// handle that appropriately.
//
// In that case, we hook at io_issue_sqe, which in turn calls io_read/io_write functions. We cannot
// use that instead io_read/io_write, as this seems to be also inlined in some kernels, but more importantly
// this is not available in modern kernels (i.e. > 5.17).

// int io_issue_sqe(struct io_kiocb *req, unsigned int issue_flags)
// 5.5 <= KERNEL_VERSION <= 5.17
SEC("kprobe/io_issue_sqe")
int BPF_KPROBE(io_issue_sqe_entry, struct io_kiocb *req, unsigned int issue_flags)
{
	bool is_rw;
	u8 opcode;

	if (!bpf_core_field_exists(req->opcode)) // kernel < 5.5
		return 0;

	probe_read(&opcode, sizeof(opcode), _(&req->opcode));
	is_rw = (opcode == IORING_OP_READV || opcode == IORING_OP_READ_FIXED || opcode == IORING_OP_READ ||
		 opcode == IORING_OP_WRITEV || opcode == IORING_OP_WRITE_FIXED || opcode == IORING_OP_WRITE);
	if (!is_rw)
		return 0;

	handle_io_readwrite(ctx, req, hook_io_issue_sqe);
	return 0;
}

// io_issue_sqe kretprobe which is mainly used for cleanup puproses.
SEC("kretprobe/io_issue_sqe")
int BPF_KRETPROBE(io_issue_sqe_exit, long ret)
{
	struct io_kiocb *req;
	bool is_rw;
	int err = 0;
	u8 opcode;

	req = handle_kretprobe(ctx, &err);
	if (!req)
		goto io_issue_sqe_exit_error;

	if (!bpf_core_field_exists(req->opcode)) // kernel < 5.5
		return 0;

	probe_read(&opcode, sizeof(opcode), _(&req->opcode));
	is_rw = (opcode == IORING_OP_READV || opcode == IORING_OP_READ_FIXED || opcode == IORING_OP_READ ||
		 opcode == IORING_OP_WRITEV || opcode == IORING_OP_WRITE_FIXED || opcode == IORING_OP_WRITE);
	if (!is_rw)
		return 0;

	err = handle_exit(req);
	if (err < 0)
		goto io_issue_sqe_exit_error;

	return 0;

io_issue_sqe_exit_error:
	inc_error(hook_io_issue_sqe, -err);
	return 0;
}
