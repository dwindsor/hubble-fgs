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
	DOCKER_ID_LENGTH = 14

	MSG_OP_UNDEF           = 0
	MSG_OP_IPV4_TCPCONNECT = 1

	MAXARGS = 20
	ARGSIZE = 64

	ARGSBUFFER = 4096

	PROGSIZE = 64
)

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
	ParentPid uint32
	Curr      MsgExec
}

type MsgPidUnix struct {
	PID       uint32
	ParentPid uint32
	UID       uint32
	Filename  string
	Args      []string
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
	Pad    [3]uint8
}

type MsgIPv4TcpConnect struct {
	Common MsgCommon
	Pid    MsgPid
	Tuple  MsgIPv4Tuple
	Kube   MsgK8s
}

type MsgIPv4TcpConnectUnix struct {
	Common MsgCommon
	Pid    MsgPidUnix
	Tuple  MsgIPv4Tuple
	Kube   MsgK8s
}
