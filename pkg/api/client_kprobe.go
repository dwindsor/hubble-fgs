//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//
package api

const (
	// 5 arguments + 1 return argument
	MaxArgsSupported = 6
	ReturnArgIndex   = MaxArgsSupported - 1
)

type MsgGenericKprobeArgPath struct {
	Index uint64
	Value string
}

func (m MsgGenericKprobeArgPath) GetIndex() uint64 {
	return m.Index
}

func (m MsgGenericKprobeArgPath) IsReturnArg() bool {
	return (m.Index == ReturnArgIndex)
}

type MsgGenericKprobeArgFile struct {
	Index uint64
	Value string
}

func (m MsgGenericKprobeArgFile) GetIndex() uint64 {
	return m.Index
}

func (m MsgGenericKprobeArgFile) IsReturnArg() bool {
	return (m.Index == ReturnArgIndex)
}

type MsgGenericKprobeArgString struct {
	Index uint64
	Value string
}

func (m MsgGenericKprobeArgString) GetIndex() uint64 {
	return m.Index
}

func (m MsgGenericKprobeArgString) IsReturnArg() bool {
	return (m.Index == ReturnArgIndex)
}

type MsgGenericKprobeArgBytes struct {
	Index    uint64
	OrigSize uint64 // if len(Value) < OrigSize, then the result was truncated
	Value    []byte
}

func (m MsgGenericKprobeArgBytes) GetIndex() uint64 {
	return m.Index
}

func (m MsgGenericKprobeArgBytes) IsReturnArg() bool {
	return m.Index == ReturnArgIndex
}

type MsgGenericKprobeArgInt struct {
	Index uint64
	Value int32
}

func (m MsgGenericKprobeArgInt) GetIndex() uint64 {
	return m.Index
}

func (m MsgGenericKprobeArgInt) IsReturnArg() bool {
	return m.Index == ReturnArgIndex
}

type MsgGenericKprobeArgSize struct {
	Index uint64
	Value uint64
}

func (m MsgGenericKprobeArgSize) GetIndex() uint64 {
	return m.Index
}

func (m MsgGenericKprobeArgSize) IsReturnArg() bool {
	return m.Index == ReturnArgIndex
}

type MsgGenericKprobeSock struct {
	Family   uint16
	Type     uint16
	Protocol uint16
	Pad      uint16
	Mark     uint32
	Priority uint32
}

type MsgGenericKprobeArgSock struct {
	Index    uint64
	Family   uint16
	Type     uint16
	Protocol uint16
	Mark     uint32
	Priority uint32
}

func (m MsgGenericKprobeArgSock) GetIndex() uint64 {
	return m.Index
}

func (m MsgGenericKprobeArgSock) IsReturnArg() bool {
	return m.Index == ReturnArgIndex
}

type MsgGenericKprobeSkb struct {
	Hash        uint32
	Len         uint32
	Priority    uint32
	Mark        uint32
	Saddr       uint32
	Daddr       uint32
	Sport       uint32
	Dport       uint32
	Proto       uint32
	SecPathLen  uint32
	SecPathOLen uint32
}

type MsgGenericKprobeArgSkb struct {
	Index       uint64
	Hash        uint32
	Len         uint32
	Priority    uint32
	Mark        uint32
	Saddr       string
	Daddr       string
	Sport       uint32
	Dport       uint32
	Proto       uint32
	SecPathLen  uint32
	SecPathOLen uint32
}

func (m MsgGenericKprobeArgSkb) GetIndex() uint64 {
	return m.Index
}

func (m MsgGenericKprobeArgSkb) IsReturnArg() bool {
	return m.Index == ReturnArgIndex
}

type MsgGenericKprobeArg interface {
	GetIndex() uint64
	IsReturnArg() bool
}

type MsgGenericKprobeUnix struct {
	Common     MsgCommon
	ProcessKey MsgExecveKey
	Id         uint64
	Action     uint64
	FuncName   string
	Args       []MsgGenericKprobeArg
}
