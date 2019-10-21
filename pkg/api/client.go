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

	MAXARGS = 20
	ARGSIZE = 64

	ARGSBUFFER = 4096

	PROGSIZE = 64
)

// API between Kernel BPF and Userspace hubble-fgs Golang agent
type MsgCommon struct {
	Op  uint8
	Pad [3]uint8
}

type MsgExec struct {
	PID      uint32
	UID      uint32
	Filename [PROGSIZE]byte
	Args     [ARGSBUFFER]byte
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
	Pad   [7]uint8
}

type MsgK8s struct {
	NetNS  uint32
	Cid    uint32
	Cgrpid uint64
	Docker [DOCKER_ID_LENGTH]byte
}

type MsgIPv4TcpConnect struct {
	Common MsgCommon
	Pid    MsgPid
	Tuple  MsgIPv4Tuple
	Kube   MsgK8s
	Return int64
}

// API between Userspace hubble-fgs Golang agent and Unix domain socket listener
type MsgExecUnix struct {
	PID      uint32
	UID      uint32
	Filename string
	Args     []string
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
	Pid    MsgPidUnix
	Tuple  MsgIPv4Tuple
	Kube   MsgK8sUnix
	Return int64
}
