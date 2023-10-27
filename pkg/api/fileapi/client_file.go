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

type HashMapFileVal struct {
	Action        uint32    `align:"action"`
	PathSize      uint32    `align:"size"`
	FullPath      [256]byte `align:"path"`
	ContainerID   [64]byte  `align:"container_id"`
	LocationFlags uint64    `align:"location_flags"` // HOST_FILE or CONTAINER_FILE
	RuleID        uint32    `align:"rule_id"`
	Pad           uint32    `align:"pad"`
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
}

type FileExecConfigMapValue struct {
	PolicyId      uint32 `align:"policy_id"`
	NumSelectors  uint32 `align:"num_selectors"`
	DefaultAction uint32 `align:"default_action"`
}

type FileExecStats struct {
	EventsGenerated uint64 `align:"events_generated"`
	EventsBlocked   uint64 `align:"events_blocked"`
	EventsSent      uint64 `align:"events_sent"`
	FailedPath      uint64 `align:"failed_path"`
	FailedDigest    uint64 `align:"failed_digest"`
}
