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

import (
	"encoding/binary"

	"github.com/isovalent/hubble-fgs/pkg/api/processapi"
	"github.com/isovalent/hubble-fgs/pkg/vtuple"
)

// Socket Flags
const (
	SOCKFLAGS_TYPE_UNKNOWN = 0x0
	SOCKFLAGS_TYPE_CONNECT = 0x1
	SOCKFLAGS_TYPE_ACCEPT  = 0x2
	SOCKFLAGS_TYPE_LISTEN  = 0x4
	// User space flag space 0x00F0
	SOCKFLAGS_TYPE_DNSREADY = 0x10
)

type MsgFGSReady struct{}

type MsgIPv4Tuple struct {
	SAddr uint32
	DAddr uint32
	DPort uint16
	SPort uint16
	Proto uint8
	// define as uint8 otherwise padding in struct breaks
	PostData [6]uint8
	Pad      [5]uint8
}

func (m *MsgIPv4Tuple) GetPostDAddr() uint32 {
	return binary.LittleEndian.Uint32(m.PostData[0:4])
}

func (m *MsgIPv4Tuple) GetPostDPort() uint16 {
	return binary.LittleEndian.Uint16(m.PostData[4:6])
}

type MsgIPv4Event struct {
	Common      processapi.MsgCommon    `align:"common"`
	Tuple       MsgIPv4Tuple            `align:"tuple"`
	Return      int64                   `align:"ret"`
	ProcessKey  processapi.MsgExecveKey `align:"key"`
	SockCookie  uint64                  `align:"socket_cookie"`
	SocketStats MsgSocketStats          `align:"stats"`
	SocketFlags uint32                  `align:"socket_flags"`
	Pad         uint32                  `align:"pad"`
}

type MsgDns struct {
	Response      bool
	RCode         uint16
	AnswerTypes   []uint32
	QuestionTypes []uint32
	Names         []string
	IPs           []string
}

type MsgIPv4DnsUnix struct {
	Common     processapi.MsgCommon
	Tuple      MsgIPv4Tuple
	Return     int64
	ProcessKey processapi.MsgExecveKey
	SockCookie uint64
	Dns        MsgDns
}

type MsgCalltrace struct {
	Stack [16]uint64
	Ret   int32
}

type MsgSocketStatsUnix struct {
	BytesSubmitted  uint64
	BytesSent       uint64
	BytesConsumed   uint64
	BytesReceived   uint64
	ConsumedSegs    uint32
	SegsIn          uint32
	SubmittedSegs   uint32
	SegsOut         uint32
	SRtt            uint32
	RetransmitSegs  uint32
	RetransmitBytes uint64
	ToZeroWindow    uint32
	SkDrop          uint32
}

type MsgSocketStats struct {
	BytesSent       uint64
	BytesReceived   uint64
	SegsIn          uint32
	SegsOut         uint32
	SRtt            uint32
	RetransmitSegs  uint32
	RetransmitBytes uint64
	ToZeroWindow    uint32
	SkDrop          uint32
}

type MsgIPv4EventUnix struct {
	Common      processapi.MsgCommon
	Tuple       MsgIPv4Tuple
	Kube        processapi.MsgK8sUnix
	Return      int64
	ProcessKey  processapi.MsgExecveKey
	SockCookie  uint64
	SocketStats MsgSocketStatsUnix
	SocketFlags uint32
}

type MsgInterfaceStats struct {
	BytesSent       uint64
	BytesReceived   uint64
	PacketsSent     uint64
	PacketsReceived uint64
	TxErrors        uint64
	RxErrors        uint64
	RxDrops         uint64
	TxDrops         uint64
}

type MsgInterface struct {
	Name          string
	Index         int
	Netns         string
	ContainerName string
}

type MsgInterfaceEventUnix struct {
	Common processapi.MsgCommon
	Kube   processapi.MsgK8sUnix
	Iface  MsgInterface
	Stats  MsgInterfaceStats
}

var MsgUnixSize uint32 = 640

type MsgCredEvent struct {
	Common       processapi.MsgCommon       `align:"common"`
	ProcessKey   processapi.MsgExecveKey    `align:"current"`
	Capabilities processapi.MsgCapabilities `align:"caps"`
}

type MsgCredEventUnix = MsgCredEvent

type MsgProcessNetworkBurstEvent struct {
	Common        processapi.MsgCommon
	ProcessKey    processapi.MsgExecveKey
	Protocol      uint32 // IP protocol
	BurstStartDir uint32 // b0=start of burst, otherwise end of burst, b16=egress, otherwise ingress
	WindowSize    uint64 // Nanoseconds
	HistAvg       uint64 // Bytes per WindowSize
	HistTrigger   uint64 // Bytes per WindowSize trigger level
	WindowAvg     uint64 // Bytes seen in WindowSize
}

type MsgProcessNetworkBurstEventUnix = MsgProcessNetworkBurstEvent

type MsgTestEvent struct {
	Common processapi.MsgCommon `align:"common"`
	Arg0   uint64               `align:"arg0"`
	Arg1   uint64               `align:"arg1"`
	Arg2   uint64               `align:"arg2"`
	Arg3   uint64               `align:"arg3"`
}

type MsgTestEventUnix = MsgTestEvent

type SensorStatus struct {
	Name    string
	Enabled bool
}

type MsgKfreeSkb struct {
	Common    processapi.MsgCommon `align:"common"`
	Calltrace MsgCalltrace         `align:"calltrace"`
	Tuple     MsgIPv4Tuple         `align:"tuple"`
}

type StackAddr struct {
	Addr   uint64
	Symbol string
}

type MsgKfreeSkbUnix struct {
	Common    processapi.MsgCommon
	Calltrace []StackAddr
	Tuple     vtuple.Impl
}
