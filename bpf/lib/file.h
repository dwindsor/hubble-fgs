#ifndef _FILE__
#define _FILE__

#define MAX_FILEPATH_SIZE 256

enum { action_invalid = 0,
       action_write = 1,
       action_read = 2,
       action_delete = 3,
       action_create = 4,
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
};

struct msg_file_path {
	char str[MAX_FILEPATH_SIZE];
	__u32 size;
	__u32 flags;
} __attribute__((packed));

struct msg_file_ops {
	struct msg_common common;
	struct msg_execve_key current;
	struct msg_file_path path;
	__u32 action;
	__u32 hook;
	__u64 ktime;
	__u64 ino;
} __attribute__((packed));

#endif
