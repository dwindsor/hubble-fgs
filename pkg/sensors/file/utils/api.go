//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package file

import "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"

const (
	InodeMapName          = "hash_map_inode_alloc"
	LpmMapName            = "lpm_trie_map_alloc"
	FilenameDigestMapName = "filename_digest_map"
	FilenamePathMapName   = "filename_path_map"

	ScannerFifoName      = "fs_scanner.sock" // this is used for tetragon-fs-scanner <-> file-sensor communication
	LocalScannerFifoPath = "/var/run"
)

var (
	ScannerFifoPath = ""
)

const (
	FilterIgnore  = 0
	FilterMatch   = 1
	FilterMonitor = 2

	AddToMap      = 0
	RemoveFromMap = 1
)

const (
	MOVE_INSIDE     = (1 << 0)
	MOVE_OUTSIDE    = (1 << 1)
	MOVE_INTERNALLY = (1 << 2)
	SRC_REG_FILE    = (1 << 3)
	SRC_DIRECTORY   = (1 << 4)
	SRC_CHAR_DEV    = (1 << 5)
	SRC_BLOCK_DEV   = (1 << 6)
	SRC_NAMED_PIPE  = (1 << 7)
	SRC_SYMLINK     = (1 << 8)
	SRC_SOCKET      = (1 << 9)
	SRC_INVALID     = (1 << 10)
	DST_NOT_EXISTS  = (1 << 11)
	DST_REG_FILE    = (1 << 12)
	DST_DIRECTORY   = (1 << 13)
	DST_CHAR_DEV    = (1 << 14)
	DST_BLOCK_DEV   = (1 << 15)
	DST_NAMED_PIPE  = (1 << 16)
	DST_SYMLINK     = (1 << 17)
	DST_SOCKET      = (1 << 18)
	DST_INVALID     = (1 << 19)
)

type FsScannerInit struct {
	PolicyName string
	Spec       v1alpha1.FileSpec
	MapDir     string
	PinPath    string
	AddToMaps  bool
}

type FsScannerDigests struct {
	Algo  int32
	Files []string
}

type FsScannerContainerDigests struct {
	Algo        int32
	Tp          []SpecPinPath
	MapDir      string
	ContainerID string
	PodNs       string
	PodName     string
	RootDir     string
	AddToMaps   bool
}

type FsScannerRename struct {
	PolicyName  string
	Spec        v1alpha1.FileSpec
	WalkPath    string
	MapDir      string
	PinPath     string
	ContainerID string
	RuleID      uint32
	Flags       uint32
}

type FsScannerRenameReply struct {
	Diff int64
}

type DigestPathMetadata struct {
	SelIdx  uint32
	PathIdx uint32
}

type SpecPinPath struct {
	PolicyName   string
	PinPath      string
	Spec         v1alpha1.FileSpec
	DigestPaths  []string
	PathMetadata map[string][]DigestPathMetadata
	UserInodeNum int64
	IsPathBased  bool
}

type FsScannerContainerInit struct {
	Tp          []SpecPinPath
	ContainerID string
	PodNs       string
	PodName     string
	RootDir     string
	MapDir      string
	AddToMaps   bool
}

type FsScannerContainerDestroy struct {
	Tp          []SpecPinPath
	ContainerID string
	MapDir      string
}
