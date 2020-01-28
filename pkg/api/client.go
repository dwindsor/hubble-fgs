// Copyright 2019 Authors of Hubble
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package api

const (
	DOCKER_ID_LENGTH = 16

	MSG_OP_UNDEF              = 0
	MSG_OP_IPV4_TCPCONNECT    = 1
	MSG_OP_IPV4_TCPCONNECTRET = 2
	MSG_OP_IPV4_BIND          = 3
	MSG_OP_IPV4_LISTEN        = 4
	MSG_OP_EXECVE             = 5

	ARGSBUFFER     = 1024 + 16
	SIZEOF_EXECVE  = 32
	MAX_SIZEOF_CWD = 256
)

// Msg Flag Definitions
const (
	EventUnknown       = 0x00
	EventExecve        = 0x01
	EventExecveAt      = 0x02
	EventProcFS        = 0x04
	EventTruncFilename = 0x08
	EventTruncArgs     = 0x10
	EventTaskWalk      = 0x20
	EventMiss          = 0x40
	EventNeedsAUID     = 0x80
	EventErrorFilename = 0x100
	EventErrorArgs     = 0x200
	EventNeedsCWD      = 0x400
	EventNoCWDSupport  = 0x800
	EventRootCWD       = 0x1000
	EventErrorCWD      = 0x2000
)

// API between Kernel BPF and Userspace hubble-fgs Golang agent
type MsgCommon struct {
	Op    uint8
	Pad   [3]uint8
	Size  uint32
	Ktime uint64
}

type OpCode int

const (
	MsgOpUndef = iota
	MsgOpIPv4TCPConnect
	MsgOpIPv4TCPConnectReturn
	MsgOpIPv4Bind
	MsgOpIPv4Listen
	MsgOpExecve
)

func (op OpCode) String() string {
	return [...]string{
		"Undef",
		"TCPConnect",
		"TCPConnectReturn",
		"TCPBind",
		"TCPListen",
		"Execve"}[op]
}

type MsgExec struct {
	Size  uint32
	PID   uint32
	UID   uint32
	AUID  uint32
	Pad   uint32
	Flags uint32
	Ktime uint64
}

type MsgPid struct {
	Parent MsgExec
	Curr   MsgExec
}

type MsgIPv4Tuple struct {
	SAddr uint32
	DAddr uint32
	DPort uint16
	SPort uint16
	Proto uint8
	Pad   [11]uint8
}

type MsgK8s struct {
	NetNS  uint32
	Cid    uint32
	Cgrpid uint64
	Docker [DOCKER_ID_LENGTH]byte
}

type MsgIPv4TcpConnect struct {
	Common MsgCommon
	Tuple  MsgIPv4Tuple
	Kube   MsgK8s
	Return int64
}

// API between Userspace hubble-fgs Golang agent and Unix domain socket listener
type MsgExecUnix struct {
	Size     uint32
	PID      uint32
	UID      uint32
	AUID     uint32
	pad      uint32
	Flags    uint32
	Ktime    uint64
	Filename string
	Args     string
}

type MsgPidUnix struct {
	Parent MsgExecUnix
	Curr   MsgExecUnix
}

type MsgK8sUnix struct {
	NetNS  uint32
	Cid    uint32
	Cgrpid uint64
	Docker string
}

type MsgIPv4TcpConnectUnix struct {
	Common MsgCommon
	Tuple  MsgIPv4Tuple
	Kube   MsgK8sUnix
	Return int64
	Pid    MsgPidUnix
}
