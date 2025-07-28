#include "bpf_file.h"

#include "process/policy_filter.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct file_exec_stats);
	__uint(max_entries, 1);
} file_exec_stats_map SEC(".maps");

static inline __attribute__((always_inline)) void inc_metric(__u32 metric)
{
	__u32 zero = 0;
	struct file_exec_stats *valp;

	if (metric >= FILE_EXEC_METRIC_MAX)
		return;

	valp = map_lookup_elem(&file_exec_stats_map, &zero);
	if (valp)
		__sync_fetch_and_add(&valp->m[metric], 1);
}

static inline __attribute__((always_inline)) int policy_filter_allow()
{
	__u32 zero = 0;
	struct file_exec_config_map_value *conf;

	conf = map_lookup_elem(&file_exec_config_map, &zero);
	if (!conf)
		return 0;
	if (!policy_filter_check(conf->policy_id))
		return 0;
	return 1;
}

SEC("lsm.s/bprm_check_security")
int BPF_PROG(security_bprm_check_lsm, struct linux_binprm *bprm)
{
	struct inode *inode;
	struct dentry *dentry, *parent_dentry;
	struct msg_file_ops *msg;
	struct file *file;
	struct exec_key key = {
		.pid_tgid = get_current_pid_tgid(),
		.bprm_ptr = (__u64)bprm,
	};
	__u32 operation = 0;
	long retval = 0;

	if (!policy_filter_allow())
		return 0;

	file = BPF_CORE_READ(bprm, file);
	if (!file)
		return 0;

	msg = get_msg_init();
	if (!msg)
		return 0;

	inode = BPF_CORE_READ(file, f_inode);
	if (!inode)
		return 0;

	dentry = BPF_CORE_READ(file, f_path.dentry);
	if (!dentry)
		return 0;

	get_ino_fs(msg, inode, dentry);

	parent_dentry = BPF_CORE_READ(dentry, d_parent);
	if (!parent_dentry)
		return 0;

	get_parent_ino_fs(msg, parent_dentry);

	msg->digest.algo = ima_file_hash(_(bprm->file), msg->digest.digest, IMA_MAX_DIGEST_SIZE);
	if (msg->digest.algo < 0)
		inc_metric(FILE_EXEC_METRIC_DIGEST_FAIL);
	msg->digest.ok = 1;

	operation = eval_exec_selectors(&msg->digest);
	if (!(operation & FILE_OP_POST))
		return 0;

	retval = d_path(_(&bprm->file->f_path), msg->path.str, 256);
	if (retval <= 0)
		inc_metric(FILE_EXEC_METRIC_PATH_FAIL);
	msg->path.size = (retval <= 0) ? (0) : (retval - 1); // exclude '\0'
	msg->path.flags = 0;

	msg->action = msg->hook = 0xFFFFFFFF;
	msg->ktime = tg_get_ktime();
	msg->tid = (__u32)get_current_pid_tgid();
	msg->operation = operation;

	// Getting a file digest requires a sleepable LSM program.
	// Sleepable programs can only use array, hash, ringbuf and local storage maps.
	// To overcome this limitation we use an fexit program to call perf_event_output
	// and send the event to the user-space. Fexit program always runs after
	// the lsm.s program and they communicate through the exec_retprobe_map map.
	retval = map_update_elem(&exec_retprobe_map, &key, msg, 0);
	if (retval != 0)
		inc_metric(FILE_EXEC_METRIC_RETPROBE_ADD_FAIL);

	return (operation & FILE_OP_BLOCK) ? -EPERM : 0;
}

SEC("fexit/security_bprm_check")
int BPF_PROG(security_bprm_check_fexit, struct linux_binprm *bprm)
{
	struct msg_file_ops *msg;
	struct exec_key key = {
		.pid_tgid = get_current_pid_tgid(),
		.bprm_ptr = (__u64)bprm,
	};

	msg = map_lookup_elem(&exec_retprobe_map, &key);
	if (!msg)
		return 0;

	perf_event_output_metric(ctx, ISO_MSG_OP_FILE, &tcpmon_map, BPF_F_CURRENT_CPU, msg, sizeof(struct msg_file_ops));

	// after sending the message we can delete the map entry
	map_delete_elem(&exec_retprobe_map, &key);

	return 0;
}
