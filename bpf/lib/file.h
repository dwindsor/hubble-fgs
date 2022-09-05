#ifndef _FILE__
#define _FILE__

#define MAX_FILEPATH_SIZE 256
#define MAX_NAME_SIZE	  128

enum { action_invalid = 0,
       action_write = 1,
       action_read = 2,
       action_delete = 3,
       action_create = 4,
       action_rmdir = 5,
       action_mkdir = 6,
       action_rename = 7,
};

// this should match the map in pkg/grpc/file/file.go
enum { hook_undef = 0,
       hook_vfs_fallocate = 1,
       hook_rw_verify_area = 2,
       hook_filemap_fault = 3,
       hook_filemap_map_pages = 4,
       hook_filemap_page_mkwrite = 5,
       hook_security_path_unlink = 6,
       hook_do_dentry_open = 7,
       hook_vfs_rmdir = 8,
       hook_vfs_mkdir = 9,
       hook_vfs_rename = 10,
};

struct vfs_mkdir_info {
	struct inode *inode;
	struct dentry *dentry;
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
};

struct msg_file_path {
	char str[MAX_FILEPATH_SIZE];
	__u32 size;
	__u32 flags;
} __attribute__((packed));

struct msg_fs_info {
	__u32 dev;
	__u32 pad;
	char name[8]; // should be enough for all file system names
	char id[8];
	__u8 uuid[16];
} __attribute__((packed));

struct msg_file_ops {
	struct msg_common common;
	struct msg_execve_key current;
	struct msg_file_path path;
	__u32 action;
	__u32 hook;
	__u64 ktime;
	__u16 imode; // unsigned short
	__u16 pad1;
	__u32 pad2;
	__u32 uid;
	__u32 gid;
	__u64 ino;
	struct msg_fs_info fs;
	__u64 parent_ino;
	struct msg_fs_info parent_fs;
	__s64 offset;
	__u32 size;
	__u32 mnt_ns;
} __attribute__((packed));

struct msg_file_split_path {
	char dir[MAX_FILEPATH_SIZE];
	char name[MAX_NAME_SIZE];
	__u32 dir_size;
	__u32 name_size;
	__u32 flags;
	__u32 pad;
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
};

struct vfs_rename_info {
	const struct path *old_dir;
	const struct path *new_dir;
	__u32 need_old, need_new;
	struct msg_file_rename_ops msg;
};

#endif
