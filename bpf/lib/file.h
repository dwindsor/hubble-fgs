#ifndef _FILE__
#define _FILE__

#define MAX_FILEPATH_SIZE 256
#define MAX_NAME_SIZE	  128

#define HOST_FILE      (1 << 0)
#define CONTAINER_FILE (1 << 1)

#define FILE_OP_POST  (1 << 0) // 0x1
#define FILE_OP_BLOCK (1 << 1) // 0x2

#define CONTAINER_ID_LEN 64

#define IMA_MAX_DIGEST_SIZE 64

#define EPERM 1 /* Operation not permitted */

enum {
	action_invalid = 0,
	action_write = 1,
	action_read = 2,
	action_delete = 3,
	action_create = 4,
	action_rmdir = 5,
	action_mkdir = 6,
	action_rename = 7,
	action_readdir = 8,
	action_chattr = 9,
	action_exec = 10,
};

// this should match the map in pkg/grpc/file/file.go
enum {
	hook_undef = 0,
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
	hook_security_mmap_file = 16,
	hook_security_inode_unlink = 17,
	hook_security_inode_setattr = 18,
	hook_security_inode_create = 19,
	hook_security_inode_mkdir = 20,
	hook_security_inode_rename = 21,
	hook_security_bprm_check = 22,
	hook_security_path_rename = 23,
	hook_max = 24,
};

#define KRETPROBE_KEY 0
#define LSM_FMOD_KEY  1

struct file_retprobe_key {
	__u64 pid_tgid;
	__u64 reg;
	__u64 flags; // KRETPROBE_KEY or LSM_FMOD_KEY
};

struct lpm_key {
	struct bpf_lpm_trie_key key;
	char data[256];
};

struct lpm_val {
	__u32 action;
	__u32 rule;
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
	__u32 rule_id;
	__u32 pad;
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

struct digest_key {
	__u8 digest[IMA_MAX_DIGEST_SIZE];
	__s32 algo; // < 0 fails to extract a file digest, >= 0 shows the hashing algorithm
	__s32 ok; // 1 if the event tried to generate a digest, 0 otherwise
};

struct file_sel_caps {
	__u32 op; // In or NotIn
	__u32 type; // Effective or Inheritable or Permitted
	__u64 filter; // Capabilities to match (ORed)
};

struct ns_filter {
	union {
		struct {
			__u32 uts_filter;
			__u32 ipc_filter;
			__u32 mnt_filter;
			__u32 pid_filter;
			__u32 pid_for_children_filter;
			__u32 net_filter;
			__u32 time_filter;
			__u32 time_for_children_filter;
			__u32 cgroup_filter;
			__u32 user_filter;
		};
		__u32 filter[ns_max_types];
	};
}; // All fields aligned so no 'packed' attribute.

struct file_sel_namespaces {
	struct msg_ns ns;
	struct ns_filter filter;
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
	__u32 tp_id;
	__u32 rule_id;
	__u32 tid;
	struct digest_key digest;
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
	__u32 tp_id;
	__u32 operation; // FILE_OP_POST or FILE_OP_BLOCK
	__u32 rule_id;
	__u32 tid;
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
	__u32 tp_id;
	__u32 num_selectors;
	__u32 policy_id;
	__u32 max_watched_dirs;
	__u32 max_watched_files;
};

struct file_exec_config_map_value {
	__u32 policy_id;
	__u32 num_selectors;
	__u32 default_action;
};

#define FILE_EXEC_METRIC_DIGEST_FAIL	   0
#define FILE_EXEC_METRIC_PATH_FAIL	   1
#define FILE_EXEC_METRIC_RETPROBE_ADD_FAIL 2
#define FILE_EXEC_METRIC_MAX		   3

struct file_exec_stats {
	__u64 m[FILE_EXEC_METRIC_MAX];
};

struct io_uring_op_key {
	__u64 file_ptr;
	__u64 pid_tgid;
};

struct io_uring_op_val {
	struct task_struct *user_task;
};

#define FILE_ERR_NO_ERROR		    0 // success
#define FILE_ERR_UNKNOWN		    1 // unknown error
#define FILE_ERR_GET_MSG_HEAP		    2 // map_lookup_elem(&file_heap_map, &zero) == 0
#define FILE_ERR_DENTRY_FROM_FILE	    3 // file->f_path.dentry == 0
#define FILE_ERR_INODE_FROM_DENTRY	    4 // dentry->d_inode == 0
#define FILE_ERR_PARENT_FROM_DENTRY	    5 // dentry->d_parent == 0
#define FILE_ERR_FILE_ARG		    6 // file == 0
#define FILE_ERR_INODE_FROM_FILE	    7 // file->f_inode == 0
#define FILE_ERR_VMA_FROM_VMF		    8 // vmf->vma == 0
#define FILE_ERR_FILE_FROM_VMA		    9 // vma->vm_file == 0
#define FILE_ERR_GET_BUFFER_HEAP	    10 // map_lookup_elem(&buffer_heap_map, &zero) == 0
#define FILE_ERR_GET_TRIE_HEAP		    11 // map_lookup_elem(&lpm_trie_heap_key, &zero) == 0
#define FILE_ERR_GET_FILE_VAL_HEAP	    12 // map_lookup_elem(&file_val_map, &zero) == 0
#define FILE_ERR_UPDATE_FILE_MAP	    13 // map_update_elem(&hash_map_file_alloc, ...) < 0
#define FILE_ERR_DENTRY_FROM_PATH	    14 // path->dentry == 0
#define FILE_ERR_DELETE_FILE_MAP	    15 // map_delete_elem(&hash_map_file_alloc, ...) < 0
#define FILE_ERR_MKDIR_INFO_HEAP_HEAP	    16 // map_lookup_elem(&vfs_mkdir_info_heap, &zero) == 0
#define FILE_ERR_UPDATE_MKDIR_RETPROBE_MAP  17 // map_update_elem(&mkdir_retprobe_map, ...) < 0
#define FILE_ERR_DELETE_MKDIR_RETPROBE_MAP  18 // map_delete_elem(&mkdir_retprobe_map, ...) < 0
#define FILE_ERR_LOOKUP_MKDIR_RETPROBE_MAP  19 // map_lookup_elem(&mkdir_retprobe_map, ...) < 0
#define FILE_ERR_UPDATE_DIR_MAP		    20 // map_update_elem(&hash_map_dir_alloc, ...) < 0
#define FILE_ERR_DELETE_DIR_MAP		    21 // map_delete_elem(&hash_map_dir_alloc, ...) < 0
#define FILE_ERR_RENAME_INFO_HEAP	    22 // map_lookup_elem(&vfs_rename_info_heap, &zero) == 0
#define FILE_ERR_UPDATE_RENAME_RETPROBE_MAP 23 // map_update_elem(&rename_retprobe_map, ...) < 0
#define FILE_ERR_DELETE_RENAME_RETPROBE_MAP 24 // map_delete_elem(&rename_retprobe_map, ...) < 0
#define FILE_ERR_LOOKUP_RENAME_RETPROBE_MAP 25 // map_lookup_elem(&rename_retprobe_map, ...) == 0
#define FILE_ERR_UPDATE_SPR_RETPROBE_MAP    26 // map_update_elem(&spr_retprobe_map, ...) < 0
#define FILE_ERR_LOOKUP_SPR_RETPROBE_MAP    27 // map_lookup_elem(&spr_retprobe_map, ...) == 0
#define FILE_ERR_DELETE_SPR_RETPROBE_MAP    28 // map_delete_elem(&spr_retprobe_map, ...) < 0
#define FILE_ERR_UPDATE_VR_RETPROBE_MAP	    29 // map_update_elem(&vr_retprobe_map, ...) < 0
#define FILE_ERR_LOOKUP_VR_RETPROBE_MAP	    30 // map_lookup_elem(&vr_retprobe_map, ...) == 0
#define FILE_ERR_DELETE_VR_RETPROBE_MAP	    31 // map_delete_elem(&vr_retprobe_map, ...) < 0
#define FILE_ERR_LOOKUP_CONFIG_MAP	    32 // map_lookup_elem(&file_config_map, &zero) == 0
#define FILE_ERR_LOOKUP_RENAME_HEAP_MAP	    33 // map_lookup_elem(&file_rename_heap_map, &zero) == 0
#define FILE_ERR_FILE_FROM_BPRM		    34 // linux_bprm->file == 0
#define FILE_ERR_UPDATE_EXEC_RETPROBE_MAP   35 // map_update_elem(&exec_retprobe_map, ...) < 0
#define FILE_ERR_DELETE_EXEC_RETPROBE_MAP   36 // map_delete_elem(&exec_retprobe_map, ...) < 0
#define FILE_ERR_UNEXPECTED		    37
#define FILE_ERR_MAX			    38

struct file_errors {
	__u64 m[hook_max][FILE_ERR_MAX];
};

#endif
