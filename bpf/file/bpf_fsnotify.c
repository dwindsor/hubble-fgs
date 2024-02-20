#include "bpf_file.h"
#include "vmlinux.h"
#include "check_file_create.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

SEC("kprobe/fsnotify")
int BPF_KPROBE(fsnotify, struct inode *to_tell, __u32 mask, const void *data, int data_is, const unsigned char *file_name, u32 cookie)
{
	struct inode *dir = to_tell;
	struct inode *file = (struct inode *)data;
	struct inode_pair inodes = { 0 };
	unsigned short i_mode;
	int err, val = 0;

	// we care only for newly created inodes
	if (mask != FS_CREATE || data_is != FSNOTIFY_EVENT_INODE)
		return 0;

	// we should chech if data is regular file (it can also be a symlink)
	i_mode = BPF_CORE_READ(file, i_mode);
	if (!S_ISREG(i_mode))
		return 0;

	inodes.ino_dir = BPF_CORE_READ(dir, i_ino);
	inodes.dev_dir = BPF_CORE_READ(dir, i_sb, s_dev);
	inodes.ino_file = BPF_CORE_READ(file, i_ino);
	inodes.dev_file = BPF_CORE_READ(file, i_sb, s_dev);

	err = map_update_elem(&fsnotify_created_files_map, &inodes, &val, 0);
	if (err < 0) {
		err = FILE_ERR_UPDATE_FSNOTIFY_MAP;
		goto fsnotify_error;
	}

	return 0;

fsnotify_error:
	inc_error(hook_fsnotify, -err);
	return 0;
}
