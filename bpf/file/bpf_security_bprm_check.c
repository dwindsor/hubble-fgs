#include "bpf_file.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

/*
 * This function handles all exec operations.
 * Returns:
 * -1 on error
 *  0 if there is no need to take any further actions
 *  1 if we need to block the operation
 */
static inline __attribute__((always_inline)) int handle_file_exec(void *ctx, struct linux_binprm *bprm)
{
	struct inode *inode;
	struct dentry *dentry, *parent_dentry;
	struct msg_file_ops *msg;
	struct hash_map_file_val *file_val = 0;
	struct file *file;
	__u32 operation = 0;
	struct digest_key *digest = 0;
#ifdef __FILE_DIGEST_LSM
	struct exec_key key = {
		.pid_tgid = get_current_pid_tgid(),
		.bprm_ptr = (__u64)bprm,
	};
#endif

	file = BPF_CORE_READ(bprm, file);
	if (!file)
		return -1;

	msg = get_msg_init();
	if (!msg)
		return -1;

	inode = BPF_CORE_READ(file, f_inode);
	if (!inode)
		return -1;

	dentry = BPF_CORE_READ(file, f_path.dentry);
	if (!dentry)
		return -1;

	get_ino_fs(msg, inode, dentry);

	parent_dentry = BPF_CORE_READ(dentry, d_parent);
	if (!parent_dentry)
		return -1;

	get_parent_ino_fs(msg, parent_dentry);

	// find this file inside the file inode map
	// we don't care if we cannot find this in the map
	// or the action is FILTER_IGNORE
	file_val = find_inode_in_map((struct bpf_map_def *)&hash_map_file_alloc, msg->ino, msg->fs.dev);
	if (!file_val)
		return 0;
	if (file_val->action == FILTER_IGNORE)
		return 0;

#ifdef __FILE_DIGEST_LSM
	msg->digest.ok = 1;
	msg->digest.algo = ima_file_hash(_(bprm->file), msg->digest.digest, IMA_MAX_DIGEST_SIZE);
	digest = &msg->digest;
#endif

	// At this point we know that we care about this access.
	// Now we can check for the selectors, if they do not match
	// we can avoid creating the message.
	// At these events we don't need to update any internal maps.
	operation = eval_selectors(action_exec, digest);
	if (!(operation & FILE_OP_POST))
		return 0;

	memcpy(msg->path.str, file_val->path, 256);
	msg->path.size = file_val->size;
	msg->path.flags = 0;
	if (file_val->location_flags == CONTAINER_FILE)
		memcpy(msg->path.container_id, file_val->container_id, CONTAINER_ID_LEN);
	msg->path.flags |= file_val->location_flags;

	msg->imode[0] = msg->imode[1] = 0;
	msg->uid[0] = msg->uid[1] = 0;
	msg->gid[0] = msg->gid[1] = 0;

	msg->action = action_exec;
	msg->hook = hook_security_bprm_check;
	msg->ktime = ktime_get_ns();
	get_mnt_ns(&msg->mnt_ns);
	msg->operation = operation;
	msg->tp_id = get_tp_id();
	msg->rule_id = file_val->rule_id;
	msg->tid = (__u32)get_current_pid_tgid();

	// Getting a file digest requires a sleepable LSM program.
	// Sleepable programs can only use array, hash, ringbuf and local storage maps.
	// To overcome this limitation we use an fexit program to call perf_event_output
	// and send the event to the user-space. Fexit program always runs after
	// the lsm.s program and they communicate through the exec_retprobe_map map.
#ifndef __FILE_DIGEST_LSM
	msg->digest.ok = 0;
	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, msg, sizeof(struct msg_file_ops));
#else
	map_update_elem(&exec_retprobe_map, &key, msg, 0);
#endif

	return (operation & FILE_OP_BLOCK) != 0;
}

#ifndef __FILE_DIGEST_LSM
SEC("kprobe/security_bprm_check")
int BPF_KPROBE(security_bprm_check, struct linux_binprm *bprm)
{
	handle_file_exec(ctx, bprm);
	return 0;
}
#endif

#ifdef __FILE_DIGEST_LSM
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

	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, msg, sizeof(struct msg_file_ops));

	// after sending the message we can delete the map entry
	map_delete_elem(&exec_retprobe_map, &key);

	return 0;
}
#endif

#ifdef __FILE_ENFORCE_LSM
#ifdef __FILE_DIGEST_LSM
SEC("lsm.s/bprm_check_security")
#else
SEC("lsm/bprm_check_security")
#endif
int BPF_PROG(security_bprm_check_lsm, struct linux_binprm *bprm)
{
	// we don't distinguish the cases of returning -1 (error) or 0 (post/ignore) for now
	if (handle_file_exec(ctx, bprm) == 1)
		return -EPERM;
	return 0;
}
#endif

#ifdef __FILE_ENFORCE_FMOD
SEC("fmod_ret/security_bprm_check")
int BPF_PROG(security_bprm_check_fmod, struct linux_binprm *bprm, int ret)
{
	if (ret != 0)
		return ret;
	// we don't distinguish the cases of returning -1 (error) or 0 (post/ignore) for now
	if (handle_file_exec(ctx, bprm) == 1)
		return -EPERM;
	return 0;
}
#endif
