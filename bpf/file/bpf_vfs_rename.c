#include "bpf_file.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

static inline __attribute__((always_inline)) void
rename_copy_dname(struct dentry *dentry, struct msg_rename_elem *pth)
{
	struct qstr d_name;
	__u32 dlen_size = 0;

	probe_read(&d_name, sizeof(d_name), _(&dentry->d_name));
	dlen_size = d_name.len;
	asm volatile("%[dlen_size] &= 0xff;\n" ::[dlen_size] "+r"(dlen_size) :);
	probe_read(pth->path.name, dlen_size, (const char *)d_name.name);
	pth->path.name_size = dlen_size;
}

static inline __attribute__((always_inline)) int
kprobe_vfs_rename(struct pt_regs *ctx, struct inode *old_dir,
		  struct dentry *old_dentry, struct inode *new_dir,
		  struct dentry *new_dentry,
		  struct inode **delegated_inode /*, unsigned int flags */)
{
	struct retprobe_key k = {
		.pid_tgid = get_current_pid_tgid(),
		.reg = PT_REGS_FP_CORE(ctx),
	};
	struct vfs_rename_info *v;
	struct inode *d_inode;
	bool walker = 0;
	struct execve_map_value *enter;
	__u32 ppid;
	umode_t i_mode;

	v = map_lookup_elem(&rename_retprobe_map, &k);
	if (!v) // If not found just return. This is a call to vfs_rename without a previous call to security_path_rename so something kernel internal.
		return 0;

	v->msg.common.op = ISO_MSG_OP_FILE_RENAME;
	v->msg.common.flags = 0;
	v->msg.common.pad[0] = 0;
	v->msg.common.pad[1] = 0;
	v->msg.common.size = sizeof(struct msg_file_rename_ops);
	v->msg.common.ktime = ktime_get_ns();

	enter = event_find_curr(&ppid, &walker);
	if (enter) {
		v->msg.current.pid = enter->key.pid;
		v->msg.current.ktime = enter->key.ktime;
	}
	v->msg.current.pad[0] = 0;
	v->msg.current.pad[1] = 0;
	v->msg.current.pad[2] = 0;
	v->msg.current.pad[3] = 0;

	v->msg.flags = 0;

	// get current inode and fs info for src (old)
	probe_read(&d_inode, sizeof(d_inode), _(&old_dentry->d_inode));
	probe_read(&(v->msg.src.ino), sizeof(v->msg.src.ino),
		   _(&d_inode->i_ino));
	probe_read(&i_mode, sizeof(i_mode), _(&d_inode->i_mode));
	get_fs_info(&(v->msg.src.fs), d_inode);

	if (S_ISREG(i_mode))
		v->msg.flags |= SRC_REG_FILE;
	else if (S_ISDIR(i_mode))
		v->msg.flags |= SRC_DIRECTORY;
	else if (S_ISCHR(i_mode))
		v->msg.flags |= SRC_CHAR_DEV;
	else if (S_ISBLK(i_mode))
		v->msg.flags |= SRC_BLOCK_DEV;
	else if (S_ISFIFO(i_mode))
		v->msg.flags |= SRC_NAMED_PIPE;
	else if (S_ISLNK(i_mode))
		v->msg.flags |= SRC_SYMLINK;
	else if (S_ISSOCK(i_mode))
		v->msg.flags |= SRC_SOCKET;
	else
		v->msg.flags |= SRC_INVALID;

	// get parent inode and fs info for src (old)
	probe_read(&(v->msg.src.parent_ino), sizeof(v->msg.src.parent_ino),
		   _(&old_dir->i_ino));
	get_fs_info(&(v->msg.src.parent_fs), old_dir);

	// get current inode and fs info for dst (new)
	probe_read(&d_inode, sizeof(d_inode), _(&new_dentry->d_inode));
	if (d_inode == 0) {
		v->msg.dst.ino = 0;
		v->msg.flags |= DST_NOT_EXISTS;
	} else {
		probe_read(&(v->msg.dst.ino), sizeof(v->msg.dst.ino),
			   _(&d_inode->i_ino));
		probe_read(&i_mode, sizeof(i_mode), _(&d_inode->i_mode));
		get_fs_info(&(v->msg.dst.fs), d_inode);

		if (S_ISREG(i_mode))
			v->msg.flags |= DST_REG_FILE;
		else if (S_ISDIR(i_mode))
			v->msg.flags |= DST_DIRECTORY;
		else if (S_ISCHR(i_mode))
			v->msg.flags |= DST_CHAR_DEV;
		else if (S_ISBLK(i_mode))
			v->msg.flags |= DST_BLOCK_DEV;
		else if (S_ISFIFO(i_mode))
			v->msg.flags |= DST_NAMED_PIPE;
		else if (S_ISLNK(i_mode))
			v->msg.flags |= DST_SYMLINK;
		else if (S_ISSOCK(i_mode))
			v->msg.flags |= DST_SOCKET;
		else
			v->msg.flags |= DST_INVALID;
	}

	// get parent inode and fs info for dst (new)
	probe_read(&(v->msg.dst.parent_ino), sizeof(v->msg.dst.parent_ino),
		   _(&new_dir->i_ino));
	get_fs_info(&(v->msg.dst.parent_fs), new_dir);

	// optimization: try to avoid doing path resolution and path copies
	// if we don't care both for src and dst
	{
		__u32 src_watched = 0, dst_watched = 0;
		struct hash_map_file_val *fv;

		if ((v->msg.flags & SRC_REG_FILE) ||
		    (v->msg.flags & SRC_DIRECTORY)) {
			fv = find_inode_in_map(
				(struct bpf_map_def *)&hash_map_dir_alloc,
				v->msg.src.parent_ino,
				v->msg.src.parent_fs.dev);
			if (fv && fv->action == FILTER_MATCH)
				src_watched = 1;
		}

		if ((v->msg.flags & DST_REG_FILE) ||
		    (v->msg.flags & DST_DIRECTORY) ||
		    (v->msg.flags & DST_NOT_EXISTS)) {
			fv = find_inode_in_map(
				(struct bpf_map_def *)&hash_map_dir_alloc,
				v->msg.dst.parent_ino,
				v->msg.dst.parent_fs.dev);
			if (fv && fv->action == FILTER_MATCH)
				dst_watched = 1;
		}

		if (!src_watched && !dst_watched) {
			map_delete_elem(&rename_retprobe_map, &k);
			return 0;
		}
	}

	// check if we care about src and get path for src (old)
	{
		struct hash_map_file_val *fval = 0;

		if ((v->msg.flags & SRC_REG_FILE) ||
		    (v->msg.flags & SRC_DIRECTORY)) {
			fval = find_inode_in_map(
				(struct bpf_map_def *)&hash_map_dir_alloc,
				v->msg.src.parent_ino,
				v->msg.src.parent_fs.dev);
		} // otherwise we don't care

		if (fval == 0) { // we care for the path not for the action
			v->need_old = 1;
		} else {
			memcpy(v->msg.src.path.dir, fval->path, 256);
			v->msg.src.path.dir_size = fval->size;
			v->msg.src.path.flags = 0;
		}

		rename_copy_dname(old_dentry, &(v->msg.src));
		v->msg.src.pad = 0;
	}

	// get path for dst (new)
	{
		struct hash_map_file_val *fval = 0;

		if ((v->msg.flags & DST_REG_FILE) ||
		    (v->msg.flags & DST_DIRECTORY) ||
		    (v->msg.flags & DST_NOT_EXISTS)) {
			fval = find_inode_in_map(
				(struct bpf_map_def *)&hash_map_dir_alloc,
				v->msg.dst.parent_ino,
				v->msg.dst.parent_fs.dev);
		} // otherwise we don't care

		if (fval == 0) { // we care for the path not for the action
			v->need_new = 1;
		} else {
			memcpy(v->msg.dst.path.dir, fval->path, 256);
			v->msg.dst.path.dir_size = fval->size;
			v->msg.dst.path.flags = 0;
		}

		rename_copy_dname(new_dentry, &(v->msg.dst));
		v->msg.dst.pad = 0;
	}

	if (v->need_old) {
		if (v->need_new) {
			map_delete_elem(&rename_retprobe_map, &k);
			return 0;
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

	return 0;
}

#ifdef VFS_PROGS_V512
struct renamedata {
	struct user_namespace *old_mnt_userns;
	struct inode *old_dir;
	struct dentry *old_dentry;
	struct user_namespace *new_mnt_userns;
	struct inode *new_dir;
	struct dentry *new_dentry;
	struct inode **delegated_inode;
	unsigned int flags;
} __randomize_layout;

__attribute__((section(("kprobe/vfs_rename")), used)) int
BPF_KPROBE(vfs_rename, struct renamedata *rd)
{
	struct renamedata d;
	probe_read(&d, sizeof(struct renamedata), rd);
	return kprobe_vfs_rename(ctx, d.old_dir, d.old_dentry, d.new_dir,
				 d.new_dentry, d.delegated_inode);
}
#else
__attribute__((section(("kprobe/vfs_rename")), used)) int
BPF_KPROBE(vfs_rename, struct inode *old_dir, struct dentry *old_dentry,
	   struct inode *new_dir, struct dentry *new_dentry,
	   struct inode **delegated_inode /*, unsigned int flags */)
{
	return kprobe_vfs_rename(ctx, old_dir, old_dentry, new_dir, new_dentry,
				 delegated_inode);
}
#endif

static inline __attribute__((always_inline)) void
resolve_missed_paths(struct vfs_rename_info *val)
{
	const struct path *res_path = 0;
	struct msg_rename_elem *pth = 0;

	// if none is 1 then res_path == 0 and we don't need to resolve any paths
	// there will be no case where both (need_old == 1) && (need_new == 1)
	if (val->need_old) {
		res_path = val->old_dir;
		pth = &(val->msg.src);
	} else if (val->need_new) {
		res_path = val->new_dir;
		pth = &(val->msg.dst);
	}

	if (res_path) {
		int buflen, error;
		char *buf = d_path_local(res_path, &buflen, &error);
		if (buf == 0)
			return;

		memcpy(pth->path.dir, buf, 256);
		pth->path.dir_size = buflen;
		pth->path.flags = error;
	}
}

static inline __attribute__((always_inline)) void
remove_inode_rename(struct msg_rename_elem *v)
{
	struct hash_map_file_key file_key;

	file_key.ino = v->ino;
	file_key.dev_major = MAJOR(v->fs.dev);
	file_key.dev_minor = MINOR(v->fs.dev);

	map_delete_elem(&hash_map_file_alloc, &file_key);
}

static inline __attribute__((always_inline)) void
update_inode_rename(struct msg_rename_elem *v,
		    struct hash_map_file_val *file_val)
{
	struct hash_map_file_key file_key;

	file_key.ino = v->ino;
	file_key.dev_major = MAJOR(v->fs.dev);
	file_key.dev_minor = MINOR(v->fs.dev);

	map_update_elem(&hash_map_file_alloc, &file_key, file_val, 0);
}

static inline __attribute__((always_inline)) struct hash_map_file_val *
generate_file_val(struct msg_rename_elem *dir, struct msg_rename_elem *name)
{
	struct hash_map_file_val *file_val = 0;
	struct hash_map_file_val *dir_val = 0;
	int zero = 0;
	char *buf = 0;
	__u32 dir_size, name_size;

	file_val = map_lookup_elem(&file_val_map, &zero);
	if (!file_val)
		return 0;

	// we can also get this from val->msg.src.path.dir but we have also to append a '/'
	// which makes that a bit more complex in ebpf
	dir_val = find_inode_in_map((struct bpf_map_def *)&hash_map_dir_alloc,
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
	asm volatile("%[dir_size] &= 0xbf;\n" ::[dir_size] "+r"(dir_size) :);
	probe_read(buf, dir_size, dir_val->path);
	file_val->size = dir_size;

	// copy file name
	name_size = name->path.name_size;
	asm volatile("%[name_size] &= 0x3f;\n" ::[name_size] "+r"(name_size) :);
	probe_read(buf + dir_size, name_size, name->path.name);
	file_val->size += name_size;

	return file_val;
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
// SRC_DIRECTORY - MOVE_INSIDE - DST_NOT_EXISTS     // traverse dst.filename and add everything to both hash_map_file_alloc and hash_map_dir_alloc
// SRC_DIRECTORY - MOVE_INSIDE - DST_DIRECTORY      // traverse dst.filename and add everything to both hash_map_file_alloc and hash_map_dir_alloc
// SRC_DIRECTORY - MOVE_OUTSIDE - DST_NOT_EXISTS    // traverse dst.filename and remove everything from both hash_map_file_alloc and hash_map_dir_alloc
// SRC_DIRECTORY - MOVE_OUTSIDE - DST_DIRECTORY     // traverse dst.filename and remove everything from both hash_map_file_alloc and hash_map_dir_alloc
// SRC_DIRECTORY - MOVE_INTERNALLY - DST_NOT_EXISTS // traverse dst.filename and update names in hash_map_dir_alloc only
// SRC_DIRECTORY - MOVE_INTERNALLY - DST_DIRECTORY  // traverse dst.filename and update names in hash_map_dir_alloc only
//
// [EBPF]
// SRC_REG_FILE - MOVE_INSIDE - DST_NOT_EXISTS      // add add src.inode to hash_map_file_alloc
// SRC_REG_FILE - MOVE_INSIDE - DST_REG_FILE        // remove dst.inode from hash_map_file_alloc *and* src.inode to hash_map_file_alloc
// SRC_REG_FILE - MOVE_OUTSIDE - DST_NOT_EXISTS     // remove src.inode from hash_map_file_alloc
// SRC_REG_FILE - MOVE_OUTSIDE - DST_REG_FILE       // remove src.inode from hash_map_file_alloc
// SRC_REG_FILE - MOVE_INTERNALLY - DST_NOT_EXISTS  // add add src.inode to hash_map_file_alloc to update the path
// SRC_REG_FILE - MOVE_INTERNALLY - DST_REG_FILE    // remove dst.inode from hash_map_file_alloc *and* src.inode to hash_map_file_alloc to update the path
__attribute__((section(("kretprobe/vfs_rename")), used)) int
BPF_KRETPROBE(vfs_rename_exit, long ret)
{
	struct retprobe_key k = {
		.pid_tgid = get_current_pid_tgid(),
		.reg = PT_REGS_FP_CORE(ctx),
	};
	struct vfs_rename_info *val;
	struct msg_file_rename_ops *msg;
	struct hash_map_file_val *file_val = 0;
	struct bpf_lpm_trie_key *key = 0;
	int zero = 0, action = 0;

	// rename failed
	if (ret) {
		map_delete_elem(&rename_retprobe_map, &k);
		return 0;
	}

	// check for the metadata from the kprobe
	val = map_lookup_elem(&rename_retprobe_map, &k);
	if (!val)
		return 0;

	// resolve any paths (if needed) for items outside of watched path
	resolve_missed_paths(val);

	if (val->msg.flags & SRC_REG_FILE) {
		if (val->msg.flags & MOVE_INSIDE) {
			// remove dst.inode from hash_map_file_alloc
			if (val->msg.flags & DST_REG_FILE) {
				remove_inode_rename(&(val->msg.dst));
			}

			// add add src.inode to hash_map_file_alloc
			if ((val->msg.flags & DST_NOT_EXISTS) ||
			    (val->msg.flags & DST_REG_FILE)) {
				file_val = generate_file_val(&(val->msg.dst),
							     &(val->msg.src));
				if (!file_val)
					return 0;

				// check if we care about the new file
				// if not just not add it in the inode map
				key = map_lookup_elem(&lpm_trie_heap_key,
						      &zero);
				if (!key)
					return 0;

				key->prefixlen = file_val->size * 8;
				memcpy(key->data, file_val->path, 256);

				action = filter_match(key);
				file_val->action = action;

				update_inode_rename(&(val->msg.src), file_val);
			}
		} else if (val->msg.flags & MOVE_INTERNALLY) {
			// remove dst.inode from hash_map_file_alloc
			if (val->msg.flags & DST_REG_FILE) {
				remove_inode_rename(&(val->msg.dst));
			}

			// add add src.inode to hash_map_file_alloc
			if ((val->msg.flags & DST_NOT_EXISTS) ||
			    (val->msg.flags & DST_REG_FILE)) {
				file_val = generate_file_val(&(val->msg.src),
							     &(val->msg.dst));
				if (!file_val)
					return 0;

				// check if we care about the new file
				// if not just not add it in the inode map
				key = map_lookup_elem(&lpm_trie_heap_key,
						      &zero);
				if (!key)
					return 0;

				key->prefixlen = file_val->size * 8;
				memcpy(key->data, file_val->path, 256);

				action = filter_match(key);
				file_val->action = action;

				update_inode_rename(&(val->msg.src), file_val);
			}
		} else if (val->msg.flags & MOVE_OUTSIDE) {
			// remove src.inode from hash_map_file_alloc
			if ((val->msg.flags & DST_NOT_EXISTS) ||
			    (val->msg.flags & DST_REG_FILE)) {
				remove_inode_rename(&(val->msg.src));
			}
		}
	}

	// now we are all done, so create the meesage to send
	msg = map_lookup_elem(&file_rename_heap_map, &zero);
	if (!msg)
		return 0;

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

	// we are done with 'val' so we can delete than entry
	map_delete_elem(&rename_retprobe_map, &k);

	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, msg,
			  sizeof(struct msg_file_rename_ops));

	return 0;
}
