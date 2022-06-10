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

type MsgFileEvent struct {
	Common     processapi.MsgCommon
	ProcessKey processapi.MsgExecveKey
	Path       MsgFilePath
	Action     uint32
	Hook       uint32
	Timestamp  uint64
	Ino        uint64
}

type MsgFileEventUnix struct {
	Common     processapi.MsgCommon
	ProcessKey processapi.MsgExecveKey
	Path       string
	Action     uint32
	Hook       uint32
	Timestamp  uint64
	Ino        uint64
}
