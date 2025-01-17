/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

#ifndef __VMLINUX_OVERLAY_H__
#define __VMLINUX_OVERLAY_H__

enum ovl_path_type {
	__OVL_PATH_UPPER = 1,
	__OVL_PATH_MERGE = 2,
	__OVL_PATH_ORIGIN = 4,
};

enum ovl_inode_flag {
	OVL_IMPURE = 0,
	OVL_WHITEOUTS = 1,
	OVL_INDEX = 2,
	OVL_UPPERDATA = 3,
	OVL_CONST_INO = 4,
	OVL_HAS_DIGEST = 5,
	OVL_VERIFIED_DIGEST = 6,
};

struct ovl_kstat {
	u64 ino;
	dev_t dev;
};

struct ovl_sb {
	struct super_block *sb;
	dev_t pseudo_dev;
	bool bad_uuid;
	bool is_lower;
};

struct ovl_config {
	char *upperdir;
	char *workdir;
	char **lowerdirs;
	bool default_permissions;
	int redirect_mode;
	int verity_mode;
	bool index;
	int uuid;
	bool nfs_export;
	int xino;
	bool metacopy;
	bool userxattr;
	bool ovl_volatile;
};

struct ovl_fs {
	unsigned int numlayer;
	unsigned int numfs;
	unsigned int numdatalayer;
	struct ovl_layer *layers;
	struct ovl_sb *fs;
	struct dentry *workbasedir;
	struct dentry *workdir;
	long int namelen;
	struct ovl_config config;
	const struct cred *creator_cred;
	bool tmpfile;
	bool noxattr;
	bool nofh;
	bool upperdir_locked;
	bool workdir_locked;
	struct inode *workbasedir_trap;
	struct inode *workdir_trap;
	int xino_mode;
	atomic_long_t last_ino;
	struct dentry *whiteout;
	bool no_shared_whiteout;
	errseq_t errseq;
};

struct ovl_layer {
	struct vfsmount *mnt;
	struct inode *trap;
	struct ovl_sb *fs;
	int idx;
	int fsid;
};

struct ovl_path {
	const struct ovl_layer *layer;
	struct dentry *dentry;
};

struct ovl_entry {
	union {
		struct {
			long unsigned int flags;
		};
		struct callback_head rcu;
	};
	unsigned int numlower;
	struct ovl_path lowerstack[0];
};

struct ovl_inode {
	const char *redirect;
	u64 version;
	long unsigned int flags;
	struct inode vfs_inode;
	struct dentry *__upperdentry;
	struct inode *lower;
	struct mutex lock;
};

#endif /* __VMLINUX_OVERLAY_H__ */
