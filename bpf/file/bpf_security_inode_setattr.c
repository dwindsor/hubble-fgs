#include "bpf_file.h"

#define OLDVAL 0
#define NEWVAL 1

char _license[] __attribute__((section("license"), used)) = "GPL";

static inline uid_t __kuid_val(kuid_t uid)
{
	return uid.val;
}
static inline gid_t __kgid_val(kgid_t gid)
{
	return gid.val;
}

static inline __attribute__((always_inline)) struct msg_file_ops *generic_chattr(struct dentry *dentry)
{
	struct inode *inode;
	struct dentry *parent_dentry;
	struct msg_file_ops *msg;
	struct hash_map_file_val *file_val = 0;

	msg = get_msg_init();
	if (!msg)
		return 0;

	inode = BPF_CORE_READ(dentry, d_inode);
	if (!inode)
		return 0;

	get_ino_fs(msg, inode, dentry);

	parent_dentry = BPF_CORE_READ(dentry, d_parent);
	if (!parent_dentry)
		return 0;

	get_parent_ino_fs(msg, parent_dentry);

	// find this file inside the file inode map
	// we don't care if we cannot find this in the map
	// or the action is FILTER_IGNORE
	file_val = find_inode_in_map((struct bpf_map_def *)&hash_map_file_alloc,
				     msg->ino, msg->fs.dev);
	if (!file_val)
		return 0;
	if (file_val->action == FILTER_IGNORE)
		return 0;

	memcpy(msg->path.str, file_val->path, 256);
	msg->path.size = file_val->size;
	msg->path.flags = 0;
	if (file_val->location_flags == CONTAINER_FILE)
		memcpy(msg->path.container_id, file_val->container_id, CONTAINER_ID_LEN);
	msg->path.flags |= file_val->location_flags;

	msg->imode[OLDVAL] = msg->imode[NEWVAL] = 0xFFFF; // UINT16_MAX
	msg->uid[OLDVAL] = msg->uid[NEWVAL] = 0xFFFFFFFF; // UINT32_MAX
	msg->gid[OLDVAL] = msg->gid[NEWVAL] = 0xFFFFFFFF; // UINT32_MAX

	msg->ktime = ktime_get_ns();
	get_mnt_ns(&msg->mnt_ns);
	msg->tp_id = get_tp_id();
	msg->rule_id = file_val->rule_id;
	msg->tid = (__u32)get_current_pid_tgid();

	return msg;
}

/*
 * This function handles all setattr operations.
 * Returns:
 * -1 on error
 *  0 if there is no need to take any further actions
 *  1 if we need to block the operation
 */
static inline __attribute__((always_inline)) int do_security_inode_setattr(void *ctx, struct dentry *dentry, struct iattr *attr)
{
	unsigned int ia_valid = BPF_CORE_READ(attr, ia_valid);
	struct msg_file_ops *msg = generic_chattr(dentry);
	if (!msg)
		return -1;

	if (ia_valid & ATTR_MODE) { // chmod
		msg->imode[OLDVAL] = BPF_CORE_READ(dentry, d_inode, i_mode); // current value
		msg->imode[NEWVAL] = BPF_CORE_READ(attr, ia_mode); // new value
		msg->action = action_chattr;
	} else if ((ia_valid & ATTR_UID) || (ia_valid & ATTR_GID)) { // chown
		msg->uid[OLDVAL] = msg->uid[NEWVAL] = __kuid_val(BPF_CORE_READ(dentry, d_inode, i_uid));
		msg->gid[OLDVAL] = msg->gid[NEWVAL] = __kgid_val(BPF_CORE_READ(dentry, d_inode, i_gid));
		if (ia_valid & ATTR_UID)
			msg->uid[NEWVAL] = __kuid_val(BPF_CORE_READ(attr, ia_uid));
		if (ia_valid & ATTR_GID)
			msg->gid[NEWVAL] = __kgid_val(BPF_CORE_READ(attr, ia_gid));
		msg->action = action_chattr;
	} else if (ia_valid & ATTR_SIZE) { // truncate
		msg->action = action_write;
	} else // we do not handle other setattr cases for now (i.e. timestamps)
		return -1;

	// At this point we know that we care about this access.
	// Now we can check for the selectors, if they do not match
	// we can avoid creating the message.
	// At these events we don't need to update any internal maps.
	msg->operation = eval_selectors(msg->action);
	if (!(msg->operation & FILE_OP_POST))
		return 0;

	msg->hook = hook_security_inode_setattr;

	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, msg, sizeof(struct msg_file_ops));

	return (msg->operation & FILE_OP_BLOCK) != 0;
}

SEC("kprobe/security_inode_setattr")
int BPF_KPROBE(security_inode_setattr, struct dentry *dentry, struct iattr *attr)
{
	do_security_inode_setattr(ctx, dentry, attr);
	return 0;
}

#ifdef __FILE_ENFORCE_LSM
SEC("lsm/inode_setattr")
int BPF_PROG(security_inode_setattr_lsm, struct dentry *dentry, struct iattr *attr)
{
	// we don't distinguish the cases of returning -1 (error) or 0 (post/ignore) for now
	if (do_security_inode_setattr(ctx, dentry, attr) == 1)
		return -EPERM;
	return 0;
}
#endif

#ifdef __FILE_ENFORCE_FMOD
SEC("fmod_ret/security_inode_setattr")
int BPF_PROG(security_inode_setattr_fmod, struct dentry *dentry, struct iattr *attr, int ret)
{
	if (ret != 0)
		return ret;
	// we don't distinguish the cases of returning -1 (error) or 0 (post/ignore) for now
	if (do_security_inode_setattr(ctx, dentry, attr) == 1)
		return -EPERM;
	return 0;
}
#endif
