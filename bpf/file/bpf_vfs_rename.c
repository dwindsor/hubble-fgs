#include "bpf_file.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

static inline __attribute__((always_inline)) void
resolve_missed_paths(struct vfs_rename_info *val, struct file_config_map_value *conf)
{
	const struct path *res_path = 0;
	int buflen = 0, error = 0;
	char *buf;

	if (!conf->has_security_path_rename) {
		struct msg_file_split_path *path = 0;

		if (val->need_old)
			path = &val->msg.src.path;
		else if (val->need_new)
			path = &val->msg.dst.path;
		else
			return;

		path->dir[0] = 0x00;
		path->dir_size = 0xffffffff; // UINT32_MAX
		path->flags = 0;
		return;
	}

	// if none is 1 then res_path == 0 and we don't need to resolve any paths
	// there will be no case where both (need_old == 1) && (need_new == 1)
	if (val->need_old)
		res_path = val->old_dir;
	else if (val->need_new)
		res_path = val->new_dir;

	if (!res_path)
		return;

	buf = d_path_local(res_path, &buflen, &error);
	if (buf == 0)
		return;

	struct msg_file_split_path *path =
		val->need_old ? &val->msg.src.path : &val->msg.dst.path;
	memcpy(path->dir, buf, 256);
	path->dir_size = buflen;
	path->flags = error;
}

static inline __attribute__((always_inline)) int
kprobe_vfs_rename(struct pt_regs *ctx, struct inode *old_dir,
		  struct dentry *old_dentry, struct inode *new_dir,
		  struct dentry *new_dentry,
		  struct inode **delegated_inode /*, unsigned int flags */)
{
	struct file_retprobe_key k = {
		.pid_tgid = get_current_pid_tgid(),
		.reg = (__u64)old_dentry,
		.flags = KRETPROBE_KEY,
	};
	struct vfs_rename_info *v;
	struct file_retprobe_key lk = {
		.pid_tgid = get_current_pid_tgid(),
		.reg = PT_REGS_FP_CORE(ctx),
		.flags = KRETPROBE_KEY,
	};
	__u64 lv = (__u64)old_dentry;
	struct inode *d_inode;
	struct file_config_map_value *conf;
	__u32 zero = 0;
	umode_t i_mode;

	conf = map_lookup_elem(&file_config_map, &zero);
	if (!conf)
		return -FILE_ERR_LOOKUP_CONFIG_MAP;

	// Now we check for an entry that was generated from security_path_rename.
	v = map_lookup_elem(&rename_retprobe_map, &k);
	if (!v) {
		if (conf->has_security_path_rename) {
			// If not found just return. This is a call to vfs_rename without a previous call to security_path_rename so something kernel internal.
			return 0;
		} else {
			// There is a case where we didn't manage to load security_path_rename due to missing CONFIG_SECURITY_PATH. In that case we can continue.
			// In ordert to do so, we need to so generate our entry in rename_retprobe_map.
			v = map_lookup_elem(&vfs_rename_info_heap, &zero);
			if (!v)
				return -FILE_ERR_RENAME_INFO_HEAP;

			v->old_dir = v->new_dir = 0;
			v->need_old = v->need_new = 0;
			v->ignore_old = v->ignore_new = 0;
			if (map_update_elem(&rename_retprobe_map, &k, v, 0) < 0)
				return -FILE_ERR_UPDATE_RENAME_RETPROBE_MAP;
			v = map_lookup_elem(&rename_retprobe_map, &k);
			if (!v) // this should never happen
				return -FILE_ERR_LOOKUP_RENAME_RETPROBE_MAP;
		}
	}

	// Create an entry for the kretprobe/vfs_rename in order to get the arguments.
	if (map_update_elem(&vr_retprobe_map, &lk, &lv, 0) < 0)
		return -FILE_ERR_UPDATE_VR_RETPROBE_MAP;

	init_rename_msg(&v->msg);

	// get current inode and fs info for src (old)
	probe_read_kernel(&d_inode, sizeof(d_inode), _(&old_dentry->d_inode));
	probe_read_kernel(&(v->msg.src.ino), sizeof(v->msg.src.ino),
			  _(&d_inode->i_ino));
	probe_read_kernel(&i_mode, sizeof(i_mode), _(&d_inode->i_mode));
	get_fs_info(&(v->msg.src.fs), &(v->msg.src.ino), d_inode, old_dentry);
	v->msg.flags |= get_rename_src_flags(i_mode);

	// get parent inode and fs info for src (old)
	probe_read_kernel(&(v->msg.src.parent_ino), sizeof(v->msg.src.parent_ino),
			  _(&old_dir->i_ino));
	get_fs_info(&(v->msg.src.parent_fs), &(v->msg.src.parent_ino), old_dir, old_dentry);

	// get current inode and fs info for dst (new)
	probe_read_kernel(&d_inode, sizeof(d_inode), _(&new_dentry->d_inode));
	if (d_inode == 0) {
		v->msg.dst.ino = 0;
		v->msg.flags |= DST_NOT_EXISTS;
	} else {
		probe_read_kernel(&(v->msg.dst.ino), sizeof(v->msg.dst.ino),
				  _(&d_inode->i_ino));
		probe_read_kernel(&i_mode, sizeof(i_mode), _(&d_inode->i_mode));
		get_fs_info(&(v->msg.dst.fs), &(v->msg.dst.ino), d_inode, new_dentry);
		v->msg.flags |= get_rename_dst_flags(i_mode);
	}

	// get parent inode and fs info for dst (new)
	probe_read_kernel(&(v->msg.dst.parent_ino), sizeof(v->msg.dst.parent_ino),
			  _(&new_dir->i_ino));
	get_fs_info(&(v->msg.dst.parent_fs), &(v->msg.dst.parent_ino), new_dir, new_dentry);

	// check if we care about src and get path for src (old)
	{
		struct inode_val *fval = 0;

		// Assuming that we will find the parent in the next step, the only
		// reason that we don't care is for the src is that the source is a
		// directory and it is explicitly ignored.
		if (v->msg.flags & SRC_DIRECTORY) {
			fval = find_inode_in_map((struct bpf_map_def *)&hash_map_inode_alloc, v->msg.src.ino, v->msg.src.fs.dev);
			if (fval && fval->action == FILTER_IGNORE)
				v->ignore_old = 1;
		}

		fval = find_inode_in_map((struct bpf_map_def *)&hash_map_inode_alloc, v->msg.src.parent_ino, v->msg.src.parent_fs.dev);
		if (fval == 0) { // we care for the path not for the action
			v->need_old = 1;
		} else {
			memcpy(v->msg.src.path.dir, fval->path, 256);
			v->msg.src.path.dir_size = fval->size;
			v->msg.src.path.flags = 0;
			if (fval->location_flags == CONTAINER_FILE) {
				memcpy(v->msg.src.path.container_id, fval->container_id, CONTAINER_ID_LEN);
			}
			v->msg.src.path.flags |= fval->location_flags;
			v->msg.rule_id = fval->rule_id;
		}

		rename_copy_dname(old_dentry, &(v->msg.src));
		v->msg.src.pad = 0;
	}

	// get path for dst (new)
	{
		struct inode_val *fval = 0;

		// Assuming that we will find the parent in the next step, the only
		// reason that we don't care is for the dst is that the destination
		// is a directory and it is explicitly ignored.
		if (v->msg.flags & DST_DIRECTORY) {
			fval = find_inode_in_map((struct bpf_map_def *)&hash_map_inode_alloc, v->msg.dst.ino, v->msg.dst.fs.dev);
			if (fval && fval->action == FILTER_IGNORE)
				v->ignore_new = 1;
		}

		fval = find_inode_in_map((struct bpf_map_def *)&hash_map_inode_alloc, v->msg.dst.parent_ino, v->msg.dst.parent_fs.dev);
		if (fval == 0) { // we care for the path not for the action
			v->need_new = 1;
		} else {
			memcpy(v->msg.dst.path.dir, fval->path, 256);
			v->msg.dst.path.dir_size = fval->size;
			v->msg.dst.path.flags = 0;
			if (fval->location_flags == CONTAINER_FILE) {
				memcpy(v->msg.dst.path.container_id, fval->container_id, CONTAINER_ID_LEN);
			}
			v->msg.dst.path.flags |= fval->location_flags;
			v->msg.rule_id = fval->rule_id; // if we watch both src and dst we report dst as rule_id
		}

		rename_copy_dname(new_dentry, &(v->msg.dst));
		v->msg.dst.pad = 0;
	}

	if (v->ignore_old || v->ignore_new) {
		if (map_delete_elem(&rename_retprobe_map, &k) < 0)
			return -FILE_ERR_DELETE_RENAME_RETPROBE_MAP;
		return 0;
	}

	if (v->need_old) {
		if (v->need_new) {
			if (map_delete_elem(&rename_retprobe_map, &k) < 0)
				return -FILE_ERR_DELETE_RENAME_RETPROBE_MAP;
			return 0; // both source and destination needs to be resolved (i.e. are outside of watched paths)
		}
		v->msg.flags |= MOVE_INSIDE;
	} else {
		v->msg.flags |=
			(v->need_new == 0) ? (MOVE_INTERNALLY) : (MOVE_OUTSIDE);
	}

	// create the event
	v->msg.action = action_rename;
	v->msg.hook = hook_vfs_rename;
	v->msg.ktime = ktime_get_ns();
	get_mnt_ns(&v->msg.mnt_ns);
	v->msg.tid = (__u32)get_current_pid_tgid();

	// resolve any paths (if needed) for items outside of watched path
	resolve_missed_paths(v, conf);

	v->operation = eval_selectors(action_rename, v->msg.flags, 0, 0, 0);

	/*
	 * We will use 2 keys:
	 * 1. To be used by kretprobe and indexed by pid_tgid, PT_REGS_FP_CORE, and flags == KRETPROBE_KEY
	 * 2. To be used by lsm/fmod_ret program and indexed by pid_tgid, old_dir, and flags == LSM_FMOD_KEY
	 * 
	 * The reason is that we don't have access to pt_regs inside lsm/fmod_ret
	 * programs and thus we can only get the second key. On the other hand, we 
	 * also don't have access to the arguments (old_dir) in the kretprobe.
	 * 
	 * In all cases, both will be deleted by the kretprobe. The kretprobe can first 
	 * delete key1 and get old_dir to delete key2. kretprobe will be called even in 
	 * the case where we block the operation.
	 */
	k.reg = (__u64)old_dir; // this is (struct inode *)
	k.flags = LSM_FMOD_KEY;
	if (map_update_elem(&rename_retprobe_map, &k, v, 0) < 0)
		return -FILE_ERR_UPDATE_RENAME_RETPROBE_MAP;

	return 0;
}

struct renamedata {
	struct user_namespace *old_mnt_userns;
	struct inode *old_dir;
	struct dentry *old_dentry;
	struct user_namespace *new_mnt_userns;
	struct inode *new_dir;
	struct dentry *new_dentry;
	struct inode **delegated_inode;
	unsigned int flags;
} __attribute__((preserve_access_index));

#ifdef __LARGE_BPF_PROG
SEC("kprobe/vfs_rename/512")
int BPF_KPROBE(vfs_rename_v512, struct renamedata *rd)
{
	struct inode *old_dir = 0, *new_dir = 0, **delegated_inode = 0;
	struct dentry *old_dentry = 0, *new_dentry = 0;
	int err;

	if (bpf_core_type_exists(struct renamedata)) {
		old_dir = BPF_CORE_READ(rd, old_dir);
		old_dentry = BPF_CORE_READ(rd, old_dentry);
		new_dir = BPF_CORE_READ(rd, new_dir);
		new_dentry = BPF_CORE_READ(rd, new_dentry);
		delegated_inode = BPF_CORE_READ(rd, delegated_inode);
	}

	err = kprobe_vfs_rename(ctx, old_dir, old_dentry, new_dir,
				new_dentry, delegated_inode);
	if (err < 0)
		inc_error(hook_vfs_rename, -err);

	return 0;
}
#endif

SEC("kprobe/vfs_rename/419")
int BPF_KPROBE(vfs_rename_v419, struct inode *old_dir, struct dentry *old_dentry,
	       struct inode *new_dir, struct dentry *new_dentry,
	       struct inode **delegated_inode /*, unsigned int flags */)
{
	int err;

	err = kprobe_vfs_rename(ctx, old_dir, old_dentry, new_dir, new_dentry,
				delegated_inode);
	if (err < 0)
		inc_error(hook_vfs_rename, -err);

	return 0;
}

static inline __attribute__((always_inline)) int
remove_inode_rename(struct msg_rename_elem *v)
{
	struct inode_key file_key;

	file_key.ino = v->ino;
	file_key.dev_major = MAJOR(v->fs.dev);
	file_key.dev_minor = MINOR(v->fs.dev);

	return map_delete_elem(&hash_map_inode_alloc, &file_key);
}

static inline __attribute__((always_inline)) int
update_inode_rename(struct msg_rename_elem *v,
		    struct inode_val *file_val)
{
	struct inode_key file_key;

	file_key.ino = v->ino;
	file_key.dev_major = MAJOR(v->fs.dev);
	file_key.dev_minor = MINOR(v->fs.dev);

	return map_update_elem(&hash_map_inode_alloc, &file_key, file_val, 0);
}

static inline __attribute__((always_inline)) struct inode_val *
generate_file_val(struct msg_rename_elem *dir, struct msg_rename_elem *name)
{
	struct inode_val *file_val = 0;
	struct inode_val *dir_val = 0;
	int zero = 0;
	char *buf = 0;
	__u32 dir_size, name_size;

	file_val = map_lookup_elem(&file_val_map, &zero);
	if (!file_val)
		return 0;

	// we can also get this from val->msg.src.path.dir but we have also to append a '/'
	// which makes that a bit more complex in ebpf
	dir_val = find_inode_in_map((struct bpf_map_def *)&hash_map_inode_alloc,
				    dir->parent_ino, dir->parent_fs.dev);
	if (!dir_val)
		return 0;
	// we need that in order to generate the path so don't return if
	// action is FILTER_IGNORE

	buf = &(file_val->path[0]);

	// file_val->path is 256 bytes
	// next, we will limit dir to be up to 192 bytes and name up to 64 bytes

	// copy parent directory path (including '/')
	dir_size = dir_val->size;
	asm volatile("%[dir_size] &= 0xbf;\n"
		     : [dir_size] "+r"(dir_size));
	probe_read_kernel(buf, dir_size, dir_val->path);
	file_val->size = dir_size;
	file_val->mode = HASH_MAP_FILE_MODE_FILE;

	// copy file name
	name_size = name->path.name_size;
	// next, we will limit name up to 64 bytes and dir to be up to 192 bytes
	// to make verifier happy.
	asm volatile("%[name_size] &= 0x3f;\n"
		     : [name_size] "+r"(name_size));
	asm volatile("%[dir_size] &= 0xbf;\n"
		     : [dir_size] "+r"(dir_size));
	probe_read_kernel(buf + dir_size, name_size, name->path.name);
	file_val->size += name_size;

	return file_val;
}

static inline __attribute__((always_inline)) struct inode *path_to_inode(const struct path *path)
{
	struct path *old_dir_path = (struct path *)path;

	return BPF_CORE_READ(old_dir_path, dentry, d_inode);
}

// we have to consider what we need to do (i.e. what we can handle here and what we need helf from the user-space)
//
// [NOOP]
// SRC_DIRECTORY - MOVE_INSIDE - DST_REG_FILE       // not possible (mv: cannot overwrite non-directory 'testfile.txt' with directory './testdir/')
// SRC_DIRECTORY - MOVE_OUTSIDE - DST_REG_FILE      // not possible (mv: cannot overwrite non-directory 'testfile.txt' with directory './testdir/')
// SRC_DIRECTORY - MOVE_INTERNALLY - DST_REG_FILE   // not possible (mv: cannot overwrite non-directory 'testfile.txt' with directory './testdir/')
// SRC_REG_FILE - MOVE_INTERNALLY - DST_DIRECTORY   // not possible(?) -- if possible nothing to do
// SRC_REG_FILE - MOVE_INSIDE - DST_DIRECTORY       // not possible(?) -- if possible do it in eBPF
// SRC_REG_FILE - MOVE_OUTSIDE - DST_DIRECTORY      // not possible(?) -- if possible do it in eBPF
//
// [GOLANG]
// SRC_DIRECTORY - MOVE_INSIDE - DST_NOT_EXISTS     // traverse dst.filename and add everything to hash_map_inode_alloc
// SRC_DIRECTORY - MOVE_INSIDE - DST_DIRECTORY      // traverse dst.filename and add everything to hash_map_inode_alloc
// SRC_DIRECTORY - MOVE_OUTSIDE - DST_NOT_EXISTS    // traverse dst.filename and remove everything from hash_map_inode_alloc
// SRC_DIRECTORY - MOVE_OUTSIDE - DST_DIRECTORY     // traverse dst.filename and remove everything from hash_map_inode_alloc
// SRC_DIRECTORY - MOVE_INTERNALLY - DST_NOT_EXISTS // traverse dst.filename and update names in hash_map_inode_alloc
// SRC_DIRECTORY - MOVE_INTERNALLY - DST_DIRECTORY  // traverse dst.filename and update names in hash_map_inode_alloc
//
// [EBPF]
// SRC_REG_FILE - MOVE_INSIDE - DST_NOT_EXISTS      // add add src.inode to hash_map_inode_alloc
// SRC_REG_FILE - MOVE_INSIDE - DST_REG_FILE        // remove dst.inode from hash_map_inode_alloc *and* src.inode to hash_map_inode_alloc
// SRC_REG_FILE - MOVE_OUTSIDE - DST_NOT_EXISTS     // remove src.inode from hash_map_inode_alloc
// SRC_REG_FILE - MOVE_OUTSIDE - DST_REG_FILE       // remove src.inode from hash_map_inode_alloc
// SRC_REG_FILE - MOVE_INTERNALLY - DST_NOT_EXISTS  // add add src.inode to hash_map_inode_alloc to update the path
// SRC_REG_FILE - MOVE_INTERNALLY - DST_REG_FILE    // remove dst.inode from hash_map_inode_alloc *and* src.inode to hash_map_inode_alloc to update the path
SEC("kretprobe/vfs_rename")
int BPF_KRETPROBE(vfs_rename_exit, long ret)
{
	struct file_retprobe_key k = {
		.pid_tgid = get_current_pid_tgid(),
		.flags = KRETPROBE_KEY,
	};
	struct vfs_rename_info *val;
	struct file_retprobe_key lk = {
		.pid_tgid = get_current_pid_tgid(),
		.reg = PT_REGS_FP_CORE(ctx),
		.flags = KRETPROBE_KEY,
	};
	struct msg_file_rename_ops *msg;
	struct inode_val *file_val = 0;
	int err, zero = 0, action = 0;
	__u64 *old_dentry, old_dir = 0;
	__u32 rule_id = 0;
	struct file_config_map_value *conf;

	old_dentry = map_lookup_elem(&vr_retprobe_map, &lk);
	if (!old_dentry) {
		err = -FILE_ERR_LOOKUP_VR_RETPROBE_MAP;
		goto vfs_rename_exit_error;
	}

	k.reg = *old_dentry;
	if (map_delete_elem(&vr_retprobe_map, &lk) < 0) {
		err = -FILE_ERR_DELETE_VR_RETPROBE_MAP;
		goto vfs_rename_exit_error;
	}

	// rename failed
	if (ret) {
		if ((val = map_lookup_elem(&rename_retprobe_map, &k))) {
			struct file_retprobe_key dkey = {
				.pid_tgid = k.pid_tgid,
				.reg = (__u64)path_to_inode(val->old_dir),
				.flags = LSM_FMOD_KEY,
			};
			map_delete_elem(&rename_retprobe_map, &dkey); // this can be deleted from the security_inode_rename program
		}
		if (map_delete_elem(&rename_retprobe_map, &k) < 0) {
			err = -FILE_ERR_DELETE_RENAME_RETPROBE_MAP;
			goto vfs_rename_exit_error;
		}
		return 0;
	}

	conf = map_lookup_elem(&file_config_map, &zero);
	if (!conf)
		return -FILE_ERR_LOOKUP_CONFIG_MAP;

	// check for the metadata from the kprobe
	val = map_lookup_elem(&rename_retprobe_map, &k);
	if (!val)
		return 0; // we don't care about that
	old_dir = (__u64)path_to_inode(val->old_dir);

	if (val->msg.flags & SRC_REG_FILE) {
		if (val->msg.flags & MOVE_INSIDE) {
			struct msg_rename_elem *name = 0;

			// remove dst.inode from hash_map_inode_alloc
			if (val->msg.flags & DST_REG_FILE) {
				if (remove_inode_rename(&(val->msg.dst)) < 0) {
					err = -FILE_ERR_DELETE_INODE_MAP;
					goto vfs_rename_exit_error;
				}
			}

			// now we need to generate the destination name
			// if the dst already exists we keep the same name
			// if the dst does not exist we keep the file name
			// from the src/
			if (val->msg.flags & DST_REG_FILE)
				name = &(val->msg.dst);
			else // (val->msg.flags & DST_NOT_EXISTS)
				name = &(val->msg.src);

			file_val = generate_file_val(&(val->msg.dst), name);
			if (!file_val)
				return 0;

			action = eval_patterns(file_val->path, file_val->size, &rule_id, conf);
			if (action < 0) // error
				return action;

			// we care only for FILTER_MATCH actions here
			if (action != FILTER_MATCH) {
				val->operation = 0; // do not send an event to the user
				goto vfs_rename_exit_out;
			}
			file_val->action = action;

			if (val->msg.src.path.flags & CONTAINER_FILE) {
				memcpy(file_val->container_id, val->msg.src.path.container_id, CONTAINER_ID_LEN);
			}
			file_val->location_flags = val->msg.src.path.flags;
			file_val->rule_id = rule_id;

			if (update_inode_rename(&(val->msg.src), file_val) < 0) {
				err = -FILE_ERR_UPDATE_INODE_MAP;
				goto vfs_rename_exit_error;
			}
		} else if (val->msg.flags & MOVE_INTERNALLY) {
			// remove dst.inode from hash_map_inode_alloc
			if (val->msg.flags & DST_REG_FILE) {
				if (remove_inode_rename(&(val->msg.dst)) < 0) {
					err = -FILE_ERR_DELETE_INODE_MAP;
					goto vfs_rename_exit_error;
				}
			}

			// add add src.inode to hash_map_inode_alloc
			if ((val->msg.flags & DST_NOT_EXISTS) ||
			    (val->msg.flags & DST_REG_FILE)) {
				file_val = generate_file_val(&(val->msg.src),
							     &(val->msg.dst));
				if (!file_val)
					return 0;

				action = eval_patterns(file_val->path, file_val->size, &rule_id, conf);
				if (action < 0) // error
					return action;

				file_val->action = action;

				if (val->msg.src.path.flags & CONTAINER_FILE) {
					memcpy(file_val->container_id, val->msg.src.path.container_id, CONTAINER_ID_LEN);
				}
				file_val->location_flags = val->msg.src.path.flags;
				file_val->rule_id = rule_id;

				if (update_inode_rename(&(val->msg.src), file_val) < 0) {
					err = -FILE_ERR_UPDATE_INODE_MAP;
					goto vfs_rename_exit_error;
				}
			}
		} else if (val->msg.flags & MOVE_OUTSIDE) {
			// remove src.inode from hash_map_inode_alloc
			if ((val->msg.flags & DST_NOT_EXISTS) ||
			    (val->msg.flags & DST_REG_FILE)) {
				if (remove_inode_rename(&(val->msg.src)) < 0) {
					err = -FILE_ERR_DELETE_INODE_MAP;
					goto vfs_rename_exit_error;
				}
			}
		}
	}

vfs_rename_exit_out:
	// now we are all done, so create the meesage to send
	msg = map_lookup_elem(&file_rename_heap_map, &zero);
	if (!msg) {
		err = -FILE_ERR_LOOKUP_RENAME_HEAP_MAP;
		goto vfs_rename_exit_error;
	}

	// a single memcpy does not work
	// "in function event_vfs_rename_ret i32 (%struct.pt_regs*): A call to built-in function 'memcpy' is not supported."
	// memcpy(msg, &(val->msg), sizeof(struct msg_file_rename_ops));
	memcpy(&(msg->common), &(val->msg.common), sizeof(struct msg_common));
	memcpy(&(msg->current), &(val->msg.current),
	       sizeof(struct msg_execve_key));
	msg->action = val->msg.action;
	msg->hook = val->msg.hook;
	msg->ktime = val->msg.ktime;
	memcpy(&(msg->src), &(val->msg.src), sizeof(struct msg_rename_elem));
	memcpy(&(msg->dst), &(val->msg.dst), sizeof(struct msg_rename_elem));
	msg->mnt_ns = val->msg.mnt_ns;
	msg->flags = val->msg.flags;
	msg->tp_id = get_tp_id();
	msg->operation = val->operation;
	msg->rule_id = val->msg.rule_id;
	msg->tid = val->msg.tid;

	// we are done with 'val' so we can delete than entry
	if (map_delete_elem(&rename_retprobe_map, &k) < 0) {
		err = -FILE_ERR_DELETE_RENAME_RETPROBE_MAP;
		goto vfs_rename_exit_error;
	}
	k.reg = old_dir;
	k.flags = LSM_FMOD_KEY;
	map_delete_elem(&rename_retprobe_map, &k); // this can be deleted from the security_inode_rename program

	// At this point we know that we care about this access.
	// Now we can check for the selectors, if they do not match
	// we can avoid creating the message.
	// In these events we have already updated any internal maps.
	if (!(msg->operation & FILE_OP_POST))
		return msg->operation;

	perf_event_output_metric(ctx, ISO_MSG_OP_FILE_RENAME, &tcpmon_map, BPF_F_CURRENT_CPU, msg,
				 sizeof(struct msg_file_rename_ops));

	return 0;

vfs_rename_exit_error:
	inc_error(hook_vfs_rename, -err);
	return 0;
}

#if defined(__FILE_ENFORCE_LSM) || defined(__FILE_ENFORCE_FMOD)
static inline __attribute__((always_inline)) int security_inode_rename(void *ctx, struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry, unsigned int flags)
{
	struct file_retprobe_key rkey = {
		.pid_tgid = get_current_pid_tgid(),
		.reg = (__u64)old_dir,
		.flags = LSM_FMOD_KEY,
	};
	struct vfs_rename_info *val;

	val = map_lookup_elem(&rename_retprobe_map, &rkey);
	if (!val)
		return 0; // we don't care about that

	if (val->operation & FILE_OP_BLOCK) {
		int zero = 0;
		struct msg_file_rename_ops *msg = map_lookup_elem(&file_rename_heap_map, &zero);
		if (!msg)
			return -FILE_ERR_LOOKUP_RENAME_HEAP_MAP;

		// a single memcpy does not work
		// "in function event_vfs_rename_ret i32 (%struct.pt_regs*): A call to built-in function 'memcpy' is not supported."
		// memcpy(msg, &(val->msg), sizeof(struct msg_file_rename_ops));
		memcpy(&(msg->common), &(val->msg.common), sizeof(struct msg_common));
		memcpy(&(msg->current), &(val->msg.current),
		       sizeof(struct msg_execve_key));
		msg->action = val->msg.action;
		msg->ktime = val->msg.ktime;
		memcpy(&(msg->src), &(val->msg.src), sizeof(struct msg_rename_elem));
		memcpy(&(msg->dst), &(val->msg.dst), sizeof(struct msg_rename_elem));
		msg->mnt_ns = val->msg.mnt_ns;
		msg->flags = val->msg.flags;
		msg->tp_id = get_tp_id();
		msg->hook = hook_security_inode_rename;
		msg->operation = FILE_OP_BLOCK;
		msg->rule_id = val->msg.rule_id;
		msg->tid = val->msg.tid;

		if (map_delete_elem(&rename_retprobe_map, &rkey) < 0)
			return -FILE_ERR_DELETE_RENAME_RETPROBE_MAP;

		perf_event_output_metric(ctx, ISO_MSG_OP_FILE_RENAME, &tcpmon_map, BPF_F_CURRENT_CPU, msg,
					 sizeof(struct msg_file_rename_ops));

		return FILE_OP_BLOCK;
	}
	return 0;
}
#endif

#ifdef __FILE_ENFORCE_LSM
SEC("lsm/inode_rename")
int BPF_PROG(security_inode_rename_lsm, struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry, unsigned int flags)
{
	int err;

	err = security_inode_rename(ctx, old_dir, old_dentry, new_dir, new_dentry, flags);
	if (err < 0) {
		inc_error(hook_security_inode_rename, -err);
		return 0;
	}

	return err & FILE_OP_BLOCK ? -EPERM : 0;
}
#endif

#ifdef __FILE_ENFORCE_FMOD
SEC("fmod_ret/security_inode_rename")
int BPF_PROG(security_inode_rename_fmod, struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry, unsigned int flags, int ret)
{
	int err;

	if (ret != 0)
		return ret;

	err = security_inode_rename(ctx, old_dir, old_dentry, new_dir, new_dentry, flags);
	if (err < 0) {
		inc_error(hook_security_inode_rename, -err);
		return 0;
	}

	return err & FILE_OP_BLOCK ? -EPERM : 0;
}
#endif
