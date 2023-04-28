#ifndef _FILE__
#define _FILE__

#define MAX_FILEPATH_SIZE 256
#define MAX_NAME_SIZE	  128

#define HOST_FILE      (1 << 0)
#define CONTAINER_FILE (1 << 1)

#define FILE_OP_POST  (1 << 0) // 0x1
#define FILE_OP_BLOCK (1 << 1) // 0x2

#define CONTAINER_ID_LEN 64

enum { action_invalid = 0,
       action_write = 1,
       action_read = 2,
       action_delete = 3,
       action_create = 4,
       action_rmdir = 5,
       action_mkdir = 6,
       action_rename = 7,
       action_readdir = 8,
       action_chattr = 9,
};

// this should match the map in pkg/grpc/file/file.go
enum { hook_undef = 0,
       hook_vfs_fallocate = 1,
       hook_security_file_permission = 2,
       hook_filemap_fault = 3,
       hook_filemap_map_pages = 4,
       hook_filemap_page_mkwrite = 5,
       hook_vfs_unlink = 6,
       hook_security_inode_rmdir = 7,
       hook_vfs_mkdir = 8,
       hook_vfs_rename = 9,
       hook_finish_open = 10,
       hook_vfs_open = 11,
       hook_iterate_dir = 12,
       hook_do_truncate = 13,
       hook_chmod_common = 14,
       hook_chown_common = 15,
};

struct retprobe_key {
	__u64 pid_tgid;
	__u64 reg;
};

struct hash_map_file_key {
	__u64 ino;
	__u32 dev_major;
	__u32 dev_minor;
};

struct hash_map_file_val {
	__u32 action;
	__u32 size;
	char path[256];
	char container_id[CONTAINER_ID_LEN];
	__u64 location_flags;
};

struct msg_file_path {
	char str[MAX_FILEPATH_SIZE];
	__u32 size;
	__u32 flags;
	char container_id[CONTAINER_ID_LEN];
};

struct msg_fs_info {
	__u32 dev;
	__u32 pad;
	char name[8]; // should be enough for all file system names
	char id[8];
	__u8 uuid[16];
};

struct msg_file_ops {
	struct msg_common common;
	struct msg_execve_key current;
	struct msg_file_path path;
	__u32 action;
	__u32 hook;
	__u64 ktime;
	__u32 operation; // FILE_OP_POST or FILE_OP_BLOCK
	__u16 imode[2]; // index 0 is the old, index 1 is the new
	__u32 uid[2];
	__u32 gid[2];
	__u64 ino;
	struct msg_fs_info fs;
	__u64 parent_ino;
	struct msg_fs_info parent_fs;
	__u32 mnt_ns;
};

struct vfs_mkdir_info {
	struct dentry *dentry;
	struct msg_file_ops msg;
	int action;
	__u32 operation;
};

struct msg_file_split_path {
	char dir[MAX_FILEPATH_SIZE];
	char name[MAX_NAME_SIZE];
	__u32 dir_size;
	__u32 name_size;
	__u32 flags;
	__u32 pad;
	char container_id[CONTAINER_ID_LEN];
};

struct msg_rename_elem {
	struct msg_file_split_path path;
	__u64 pad;
	__u64 ino;
	struct msg_fs_info fs;
	__u64 parent_ino;
	struct msg_fs_info parent_fs;
};

struct msg_file_rename_ops {
	struct msg_common common;
	struct msg_execve_key current;
	__u32 action;
	__u32 hook;
	__u64 ktime;
	struct msg_rename_elem src;
	struct msg_rename_elem dst;
	__u32 mnt_ns;
	__u32 flags;
	__u32 tc_id;
	__u32 operation; // FILE_OP_POST or FILE_OP_BLOCK
};

struct vfs_rename_info {
	const struct path *old_dir;
	const struct path *new_dir;
	__u32 need_old, need_new;
	struct msg_file_rename_ops msg;
	__u32 operation;
};

struct file_config_map_value {
	__u32 has_security_path_rename;
	__u32 action_value;
};

#endif
