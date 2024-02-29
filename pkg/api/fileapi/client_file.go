//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package fileapi

import "github.com/cilium/tetragon/pkg/api/processapi"

// should match MAX_FILE_PATTERNS in bpf_file.h
const PatternMapSize = 32

type PatternValue struct {
	Prefix    [256]byte `align:"prefix"`
	PrefixLen uint32    `align:"prefix_len"`
	Suffix    [256]byte `align:"suffix"`
	SuffixLen uint32    `align:"suffix_len"`
	Action    uint32    `align:"action"`
	Rule      uint32    `align:"rule"`
}

type LPMMapKey struct {
	Prefixlen uint32    `align:"key"`
	Data      [256]byte `align:"data"`
}

type LPMMapValue struct {
	Action uint32 `align:"action"`
	Rule   uint32 `align:"rule"`
}

type HashMapFileKey struct {
	Ino      uint64 `align:"ino"`
	DevMajor uint32 `align:"dev_major"`
	DevMinor uint32 `align:"dev_minor"`
}

const (
	HOST_FILE      = (1 << 0)
	CONTAINER_FILE = (1 << 1)
)

const (
	HashMapFileModeUnknown   = 0
	HashMapFileModeFile      = 1
	HashMapFileModeDirectory = 2
)

type HashMapFileVal struct {
	Action        uint32    `align:"action"`
	PathSize      uint32    `align:"size"`
	FullPath      [256]byte `align:"path"`
	ContainerID   [64]byte  `align:"container_id"`
	LocationFlags uint64    `align:"location_flags"` // HOST_FILE or CONTAINER_FILE
	RuleID        uint32    `align:"rule_id"`
	Mode          uint32    `align:"mode"` // HashMapFileMode*
}

type MsgFilePath struct {
	Str         [256]byte `align:"str"` // should match MAX_FILEPATH_SIZE in bpf/lib/generic.h
	Size        uint32    `align:"size"`
	Flags       uint32    `align:"flags"`
	ContainerID [64]byte  `align:"container_id"`
}

type MsgFsInfo struct {
	SDev  uint32   `align:"dev"`
	Pad   uint32   `align:"pad"`
	SName [8]byte  `align:"name"`
	SId   [8]byte  `align:"id"`
	SUuid [16]byte `align:"uuid"`
}

type DigestKey struct {
	Digest [64]uint8 `align:"digest"`
	Algo   int32     `align:"algo"`
	Ok     int32     `align:"ok"`
}

type SelCaps struct {
	Op     uint32 `align:"op"`     // In or NotIn
	Type   uint32 `align:"type"`   // Effective or Inheritable or Permitted
	Filter uint64 `align:"filter"` // Capabilities to match (ORed)
}

type SelNsFilter struct {
	UtsFilter       uint32 // 0 Equal, 1 NotEqual
	IpcFilter       uint32
	MntFilter       uint32
	PidFilter       uint32
	PidChildFilter  uint32
	NetFilter       uint32
	TimeFilter      uint32
	TimeChildFilter uint32
	CgroupFilter    uint32
	UserFilter      uint32
}

type SelNs struct {
	Ns     processapi.MsgNamespaces `align:"ns"`
	Filter SelNsFilter              `align:"filter"`
}

type MsgFileEvent struct {
	Common     processapi.MsgCommon    `align:"common"`
	ProcessKey processapi.MsgExecveKey `align:"current"`
	Path       MsgFilePath             `align:"path"`
	Action     uint32                  `align:"action"`
	Hook       uint32                  `align:"hook"`
	Timestamp  uint64                  `align:"ktime"`
	Operation  uint32                  `align:"operation"`
	Imode      [2]uint16               `align:"imode"`
	Uid        [2]uint32               `align:"uid"`
	Gid        [2]uint32               `align:"gid"`
	Ino        uint64                  `align:"ino"`
	Fs         MsgFsInfo               `align:"fs"`
	ParentIno  uint64                  `align:"parent_ino"`
	ParentFs   MsgFsInfo               `align:"parent_fs"`
	MntNs      uint32                  `align:"mnt_ns"`
	TpId       uint32                  `align:"tp_id"`
	RuleID     uint32                  `align:"rule_id"`
	Tid        uint32                  `align:"tid"`
	Digest     DigestKey               `align:"digest"`
}

type MsgFileSplitPath struct {
	Dir         [256]byte `align:"dir"`  // should match MAX_FILEPATH_SIZE in bpf/lib/generic.h
	Name        [128]byte `align:"name"` // should match MAX_NAME_SIZE in bpf/lib/generic.h
	DirSize     uint32    `align:"dir_size"`
	NameSize    uint32    `align:"name_size"`
	Flags       uint32    `align:"flags"`
	Pad         uint32    `align:"pad"`
	ContainerID [64]byte  `align:"container_id"`
}

type MsgRenameElem struct {
	Path      MsgFileSplitPath `align:"path"`
	Pad       uint64           `align:"pad"`
	Ino       uint64           `align:"ino"`
	Fs        MsgFsInfo        `align:"fs"`
	ParentIno uint64           `align:"parent_ino"`
	ParentFs  MsgFsInfo        `align:"parent_fs"`
}

type MsgFileRenameEvent struct {
	Common     processapi.MsgCommon    `align:"common"`
	ProcessKey processapi.MsgExecveKey `align:"current"`
	Action     uint32                  `align:"action"`
	Hook       uint32                  `align:"hook"`
	Timestamp  uint64                  `align:"ktime"`
	Src        MsgRenameElem           `align:"src"`
	Dst        MsgRenameElem           `align:"dst"`
	MntNs      uint32                  `align:"mnt_ns"`
	Flags      uint32                  `align:"flags"`
	TpId       uint32                  `align:"tp_id"`
	Operation  uint32                  `align:"operation"`
	RuleID     uint32                  `align:"rule_id"`
	Tid        uint32                  `align:"tid"`
}

type FileConfigMapValue struct {
	HasSecurityPathRename uint32 `align:"has_security_path_rename"`
	TpId                  uint32 `align:"tp_id"`
	NumSelectors          uint32 `align:"num_selectors"`
	PolicyId              uint32 `align:"policy_id"`
	MaxWatchedInodes      uint32 `align:"max_watched_inodes"`
	IsLessThan419         uint32 `align:"is_less_than_419"`
	NumPatterns           uint32 `align:"num_patterns"`
}

type FileExecConfigMapValue struct {
	PolicyId      uint32 `align:"policy_id"`
	NumSelectors  uint32 `align:"num_selectors"`
	DefaultAction uint32 `align:"default_action"`
}

const (
	FileExecMetricDigestFail      = 0
	FileExecMetricPathFail        = 1
	FileExecMetricRetprobeAddFail = 2
	FileExecMetricMax             = 3
)

var FileExecMetricTable = map[int]string{
	FileExecMetricDigestFail:      "digest_fail",
	FileExecMetricPathFail:        "path_fail",
	FileExecMetricRetprobeAddFail: "retprobe_add_fail",
}

type FileExecStats struct {
	M [FileExecMetricMax]uint64 `align:"m"`
}

const (
	FileErrNoError                  = 0
	FileErrUnknown                  = 1
	FileErrGetMsgHeap               = 2
	FileErrDentryFromFile           = 3
	FileErrInodeFromDentry          = 4
	FileErrParentFromDentry         = 5
	FileErrFileArg                  = 6
	FileErrInodeFromFile            = 7
	FileErrVmaFromVmf               = 8
	FileErrFileFromVma              = 9
	FileErrGetBufferHeap            = 10
	FileErrGetTrieHeap              = 11
	FileErrGetFileValHeap           = 12
	FileErrUpdateInodeMap           = 13
	FileErrDentryFromPath           = 14
	FileErrDeleteInodeMap           = 15
	FileErrMkdirInfoHeap            = 16
	FileErrUpdateMkdirRetprobeMap   = 17
	FileErrDeleteMkdirRetprobeMap   = 18
	FileErrLookupMkdirRetprobeMap   = 19
	FileErrRenameInfoHeap           = 20
	FileErrUpdateRenameRetprobeMap  = 21
	FileErrDeleteRenameRetprobeMap  = 22
	FileErrLookupRenameRetprobeMap  = 23
	FileErrUpdateSprRetprobeMap     = 24
	FileErrLookupSprRetprobeMap     = 25
	FileErrDeleteSprRetprobeMap     = 26
	FileErrUpdateVrRetprobeMap      = 27
	FileErrLookupVrRetprobeMap      = 28
	FileErrDeleteVrRetprobeMap      = 29
	FileErrLookupConfigMap          = 30
	FileErrLookupRenameHeapMap      = 31
	FileErrFileFromBprm             = 32
	FileErrUpdateExecRetProbeMap    = 33
	FileErrDeleteExecRetprobeMap    = 34
	FileErrUpdateIoUringRetprobeMap = 35
	FileErrDeleteIoUringRetprobeMap = 36
	FileErrLookupIoUringRetprobeMap = 37
	FileErrUpdateIoUringMap         = 38
	FileErrDeleteIoUringMap         = 39
	FileErrIoUringTask              = 40
	FileErrUpdateFsNotifyMap        = 41
	FileErrDeleteFsNotifyMap        = 42
	FileErrLookupPatternsMap        = 43
	FileErrUnexpected               = 44
	FileErrMax                      = 45
)

const (
	FileHookUndef                  = 0
	FileHookVfsFallocate           = 1
	FileHookSecurityFilePermission = 2
	FileHookFilemapFault           = 3
	FileHookFilemapMapPages        = 4
	FileHookFilemapPageMkwrite     = 5
	FileHookVfsUnlink              = 6
	FileHookSecurityInodeRmdir     = 7
	FileHookVfsMkdir               = 8
	FileHookVfsRename              = 9
	FileHookFinishOpen             = 10
	FileHookVfsOpen                = 11
	FileHookIterateDir             = 12
	FileHookDoTruncate             = 13
	FileHookChmodCommon            = 14
	FileHookChownCommon            = 15
	FileHookSecurityMmapFile       = 16
	FileHookSecurityInodeUnlink    = 17
	FileHookSecurityInodeSetattr   = 18
	FileHookSecurityInodeCreate    = 19
	FileHookSecurityInodeMkdir     = 20
	FileHookSecurityInodeRename    = 21
	FileHookSecurityBprmCheck      = 22
	FileHookSecurityPathRename     = 23
	FileHookIoRead                 = 24
	FileHookIoWrite                = 25
	FileHookIoIssueSqe             = 26
	FileHookFsNotify               = 27
	FileHookMax                    = 28
)

type FileErrors struct {
	M [FileHookMax][FileErrMax]uint64 `align:"m"`
}
