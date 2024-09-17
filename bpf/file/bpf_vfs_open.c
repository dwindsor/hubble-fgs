#include "bpf_file.h"
#include "check_file_create.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

SEC("kprobe/vfs_open")
int BPF_KPROBE(vfs_open, const struct path *path, struct file *file)
{
	struct dentry *dentry;
	__u32 err, zero = 0;
	__u32 f_mode;
	struct file_config_map_value *conf;

	probe_read_kernel(&dentry, sizeof(struct dentry *), _(&path->dentry));
	if (!dentry) {
		err = FILE_ERR_DENTRY_FROM_PATH;
		goto vfs_open_error;
	}

	conf = map_lookup_elem(&file_config_map, &zero);
	if (!conf) {
		err = FILE_ERR_LOOKUP_CONFIG_MAP;
		goto vfs_open_error;
	}

	if (conf->is_less_than_419) {
		struct inode_pair inodes = { 0 };

		inodes.ino_dir = BPF_CORE_READ(dentry, d_parent, d_inode, i_ino);
		inodes.dev_dir = BPF_CORE_READ(dentry, d_parent, d_inode, i_sb, s_dev);
		inodes.ino_file = BPF_CORE_READ(dentry, d_inode, i_ino);
		inodes.dev_file = BPF_CORE_READ(dentry, d_inode, i_sb, s_dev);

		if (!map_lookup_elem(&fsnotify_created_files_map, &inodes))
			return 0; // no file created

		err = map_delete_elem(&fsnotify_created_files_map, &inodes);
		if (err < 0) {
			err = FILE_ERR_DELETE_FSNOTIFY_MAP;
			goto vfs_open_error;
		}
	} else {
		probe_read_kernel(&f_mode, sizeof(f_mode), _(&file->f_mode));
		if ((f_mode & FMODE_CREATED) == 0)
			return 0; // no file created
	}

	err = check_file_create(ctx, file, dentry, hook_vfs_open);
	if (err < 0)
		goto vfs_open_error;

	return 0;

vfs_open_error:
	inc_error(hook_vfs_open, -err);
	return 0;
}
