// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build !windows

package file

import (
	"golang.org/x/sys/unix"
)

var (
	// values from https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/magic.h
	// the list is not exhaustive yet but represents the most common file systems
	FsNameMagic = map[string]uint32{
		"sysfs":       unix.SYSFS_MAGIC,
		"proc":        unix.PROC_SUPER_MAGIC,
		"debugfs":     unix.DEBUGFS_MAGIC,
		"securityfs":  unix.SECURITYFS_MAGIC,
		"squashfs":    unix.SQUASHFS_MAGIC,
		"overlayfs":   unix.OVERLAYFS_SUPER_MAGIC,
		"tracefs":     unix.TRACEFS_MAGIC,
		"bpffs":       unix.BPF_FS_MAGIC,
		"fuse":        unix.FUSE_SUPER_MAGIC,
		"ext4":        unix.EXT4_SUPER_MAGIC,
		"ext3":        unix.EXT3_SUPER_MAGIC,
		"ext2":        unix.EXT2_SUPER_MAGIC,
		"xfs":         unix.XFS_SUPER_MAGIC,
		"ramfs":       unix.RAMFS_MAGIC,
		"tmpfs":       unix.TMPFS_MAGIC,
		"ceph":        unix.CEPH_SUPER_MAGIC,
		"btrfs":       unix.BTRFS_SUPER_MAGIC,
		"smb":         unix.SMB_SUPER_MAGIC,
		"smb2":        unix.SMB2_SUPER_MAGIC,
		"cifs":        unix.CIFS_SUPER_MAGIC,
		"cgroup":      unix.CGROUP_SUPER_MAGIC,
		"cgroup2":     unix.CGROUP2_SUPER_MAGIC,
		"binfmt_misc": unix.BINFMTFS_MAGIC,
		"nfs":         unix.NSFS_MAGIC,
		"pstore":      unix.PSTOREFS_MAGIC,
		"autofs":      unix.AUTOFS_SUPER_MAGIC,
		"nsfs":        unix.NSFS_MAGIC,
		"devpts":      unix.DEVPTS_SUPER_MAGIC,
	}

	InodeTypes = map[string]uint32{
		"link":    unix.S_IFLNK,
		"file":    unix.S_IFREG,
		"dir":     unix.S_IFDIR,
		"chardev": unix.S_IFCHR,
		"blkdev":  unix.S_IFBLK,
	}
)
