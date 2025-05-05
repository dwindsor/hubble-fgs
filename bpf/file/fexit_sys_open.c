#define __V61_BPF_PROG
#define __ENABLE_GLOB_SUPPORT
#define __ENABLE_OPENRAW_SUPPORT
#include "bpf_file.h"
#include "dispatcher.h"
#include "getname.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

#define AT_FDCWD -100

#define O_WRONLY 00000001
#define O_CREAT	 00000100
#define O_TRUNC	 00001000

static long BPF_FUNC(copy_from_user, void *dst, __u32 size, const void *user_ptr);
static long BPF_FUNC(probe_read_user_str, void *dst, u32 size, const void *unsafe_ptr);

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct msg_file_openraw_ops);
	__uint(max_entries, 1);
} file_openraw_heap_map SEC(".maps");

static struct msg_file_openraw_ops *get_msg_openraw_init()
{
	struct msg_file_openraw_ops *msg;
	bool walker = 0;
	int zero = 0;
	struct execve_map_value *enter;
	__u32 ppid;

	msg = map_lookup_elem(&file_openraw_heap_map, &zero);
	if (!msg)
		return 0;

	memset(msg, 0, sizeof(struct msg_file_openraw_ops));

	msg->common.op = ISO_MSG_OP_FILE_OPENRAW;
	msg->common.size = sizeof(struct msg_file_openraw_ops);
	msg->common.ktime = ktime_get_ns();

	enter = event_find_curr(&ppid, &walker);
	if (enter) {
		msg->current.pid = enter->key.pid;
		msg->current.ktime = enter->key.ktime;
	}

	return msg;
}

static inline __attribute__((always_inline)) int handle_open_raw(void *ctx, const char *filename, __u32 flags, __u32 hook, int dfd, int ret)
{
	struct msg_file_openraw_ops *msg;
	struct kpath *kpath;
	__u64 map_key = 0;
	__u32 operation = 0;
	__u32 msg_id = 0;
	__u32 rule_id = 0;

	if (!policy_filter_match())
		return 0;

	msg = get_msg_openraw_init();
	if (!msg)
		return -FILE_ERR_GET_MSG_HEAP;

	map_key = (__u64)filename;
	kpath = map_lookup_elem(&open_user_to_kernel_path, &map_key);
	if (!kpath)
		return 0;

	probe_read_kernel(msg->path.str, MAX_FILEPATH_SIZE, kpath->str);
	msg->path.size = kpath->size;
	msg->path.flags = kpath->flags;

	if (!__sync_sub_and_fetch(&kpath->refcnt, 1))
		map_delete_elem(&open_user_to_kernel_path, &map_key);

	msg->is_relative_path = msg->path.str[0] != '/';
	if (msg->is_relative_path) { // in that case, we also need the dfd
		int flags = 0, size;
		char *buffer;
		struct task_struct *tsk;
		struct path *dir_path = 0;
		long ret;

		tsk = (struct task_struct *)get_current_task_btf();

		if (dfd == AT_FDCWD) { // we need to get the cwd
			struct fs_struct *fs;

			fs = BPF_CORE_READ(tsk, fs);
			dir_path = _(&fs->pwd);
		} else { // we need to get the file pointer that is related to dfd file descriptor
			struct file **fd, *file;

			fd = BPF_CORE_READ(tsk, files, fdt, fd);

			probe_read_kernel(&file, sizeof(struct file *), (__u8 *)fd + (dfd * sizeof(struct file *)));
			if (!file)
				return 0;

			dir_path = _(&file->f_path);
		}

		// compute the path of the directory
		buffer = d_path_local(dir_path, &size, &flags);
		if (!buffer)
			return 0;

		// read the path of the directory
		ret = probe_read_kernel_str(msg->dir.str, MAX_FILEPATH_SIZE, buffer);
		msg->dir.size = (ret > 0) ? (ret - 1) : (0);
		msg->dir.flags = 0;

		// read fs information related to the directory
		msg->dir_ino = BPF_CORE_READ(dir_path, dentry, d_inode, i_ino);
		get_fs_info(&msg->dir_fs, &msg->dir_ino, BPF_CORE_READ(dir_path, dentry, d_inode), BPF_CORE_READ(dir_path, dentry));
	}

	msg->open_flags = flags;
	msg->retval = ret;

	operation = eval_selectors((struct sel_args){ action_openraw, flags, ret }, 0, (struct sel_path){ msg->path.str, msg->path.size }, &msg_id);
	if (!(operation & FILE_OP_POST))
		return 0;

	msg->action = action_openraw;
	msg->hook = hook;
	msg->ktime = ktime_get_ns();
	msg->operation = operation;
	msg->tp_id = get_tp_id();
	msg->rule_id = rule_id;
	msg->msg_id = msg_id;
	msg->tid = (__u32)get_current_pid_tgid();

	perf_event_output_metric(ctx, ISO_MSG_OP_FILE_OPENRAW, &tcpmon_map, BPF_F_CURRENT_CPU, msg, sizeof(struct msg_file_openraw_ops));

	return 0;
}

SEC(FEXIT(ARCH, "sys_open"))
int BPF_PROG(sys_open, const struct pt_regs *regs, int ret) // SYSCALL_DEFINE3(open, const char __user *, filename, int, flags, umode_t, mode)
{
	const char *filename = (const char *)PT_REGS_PARM1_CORE_SYSCALL(regs); // user memory
	int flags = PT_REGS_PARM2_CORE_SYSCALL(regs);
	int dfd = AT_FDCWD;

	handle_open_raw(ctx, filename, flags, hook_sys_open, dfd, ret);

	return 0;
}

SEC(FEXIT(ARCH, "sys_openat"))
int BPF_PROG(sys_openat, const struct pt_regs *regs, int ret) // SYSCALL_DEFINE4(openat, int, dfd, const char __user *, filename, int, flags, umode_t, mode)
{
	int dfd = PT_REGS_PARM1_CORE_SYSCALL(regs);
	const char *filename = (const char *)PT_REGS_PARM2_CORE_SYSCALL(regs); // user memory
	int flags = PT_REGS_PARM3_CORE_SYSCALL(regs);

	handle_open_raw(ctx, filename, flags, hook_sys_openat, dfd, ret);

	return 0;
}

SEC(FEXIT(ARCH, "sys_openat2"))
int BPF_PROG(sys_openat2, const struct pt_regs *regs, int ret) // SYSCALL_DEFINE4(openat2, int, dfd, const char __user *, filename, struct open_how __user *, how, size_t, usize)
{
	int dfd = PT_REGS_PARM1_CORE_SYSCALL(regs);
	const char *filename = (const char *)PT_REGS_PARM2_CORE_SYSCALL(regs); // user memory
	struct open_how *how = (struct open_how *)PT_REGS_PARM3_CORE_SYSCALL(regs);

	handle_open_raw(ctx, filename, BPF_CORE_READ(how, flags), hook_sys_openat2, dfd, ret);

	return 0;
}

SEC(FEXIT(ARCH, "sys_creat"))
int BPF_PROG(sys_creat, const struct pt_regs *regs, int ret) // SYSCALL_DEFINE2(creat, const char __user *, pathname, umode_t, mode)
{
	const char *filename = (const char *)PT_REGS_PARM1_CORE_SYSCALL(regs); // user memory
	int flags = O_CREAT | O_WRONLY | O_TRUNC;
	int dfd = AT_FDCWD;

	handle_open_raw(ctx, filename, flags, hook_sys_creat, dfd, ret);

	return 0;
}

SEC("fexit/io_openat2")
int BPF_PROG(io_openat2, struct io_kiocb *req, unsigned int issue_flags, int ret) // for io_uring
{
	struct io_cmd_data data = BPF_CORE_READ(req, cmd);
	struct io_open *open = (struct io_open *)&data;
	struct filename *filename = BPF_CORE_READ(open, filename);
	int flags = BPF_CORE_READ(open, how.flags);
	int dfd = BPF_CORE_READ(open, dfd);
	int retval = BPF_CORE_READ(req, cqe.res);

	handle_open_raw(ctx, BPF_CORE_READ(filename, uptr), flags, hook_io_openat2, dfd, (ret == 0) ? (retval) : (ret));

	return 0;
}