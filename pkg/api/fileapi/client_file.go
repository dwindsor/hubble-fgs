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

type MsgFilePath struct {
	Str   [256]byte // should match MAX_FILEPATH_SIZE in bpf/lib/generic.h
	Size  uint32
	Flags uint32
}

type MsgFsInfo struct {
	SDev  uint32
	Pad   uint32
	SName [8]byte
	SId   [8]byte
	SUuid [16]byte
}

type MsgFileEvent struct {
	Common     processapi.MsgCommon
	ProcessKey processapi.MsgExecveKey
	Path       MsgFilePath
	Action     uint32
	Hook       uint32
	Timestamp  uint64
	Imode      uint16
	Pad1       uint16
	Pad2       uint32
	Uid        uint32
	Gid        uint32
	Ino        uint64
	Fs         MsgFsInfo
	ParentIno  uint64
	ParentFs   MsgFsInfo
}
