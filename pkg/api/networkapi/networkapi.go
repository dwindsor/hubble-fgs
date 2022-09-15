package networkapi

import (
	"encoding/binary"

	"github.com/cilium/tetragon/pkg/api/processapi"
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

const (
	// MsgUnixSize of burst msg
	MsgUnixSize uint32 = 640
)

type MsgIPv4HTTPTuple struct {
	SAddr uint32
	DAddr uint32
	DPort uint16
	SPort uint16
	Proto uint8
	// define as uint8 otherwise padding in struct breaks
	PostData [6]uint8
	Pad      [5]uint8
}

type MsgIPTuple struct {
	SAddr [2]uint64
	DAddr [2]uint64
	DPort uint16
	SPort uint16
	Proto uint8
	// define as uint8 otherwise padding in struct breaks
	PostData [6]uint8
	IPv6     uint8
	Pad      [4]uint8
}

func (m *MsgIPTuple) GetPostDAddr() uint32 {
	return binary.LittleEndian.Uint32(m.PostData[0:4])
}

func (m *MsgIPTuple) GetPostDPort() uint16 {
	return binary.LittleEndian.Uint16(m.PostData[4:6])
}

type MsgIPEvent struct {
	Common      processapi.MsgCommon    `align:"common"`
	Tuple       MsgIPTuple              `align:"tuple"`
	Return      int64                   `align:"ret"`
	ProcessKey  processapi.MsgExecveKey `align:"key"`
	SockCookie  uint64                  `align:"socket_cookie"`
	SocketStats MsgSocketStats          `align:"stats"`
	SocketFlags uint32                  `align:"socket_flags"`
	Pad         uint32                  `align:"pad"`
}

type MsgSocketStatsUnix struct {
	BytesSubmitted   uint64
	BytesSent        uint64
	BytesConsumed    uint64
	BytesReceived    uint64
	ConsumedSegs     uint32
	SegsIn           uint32
	SubmittedSegs    uint32
	SegsOut          uint32
	SRtt             uint32
	RetransmitSegs   uint32
	RetransmitBytes  uint64
	ToZeroWindow     uint32
	SkDrop           uint32
	SkbConsumeMisses uint32
}

type MsgSocketStats struct {
	BytesSent        uint64
	BytesReceived    uint64
	SegsIn           uint32
	SegsOut          uint32
	SRtt             uint32
	RetransmitSegs   uint32
	RetransmitBytes  uint64
	ToZeroWindow     uint32
	SkDrop           uint32
	SkbConsumeMisses uint32
}

type MsgIPEventUnix struct {
	Common      processapi.MsgCommon
	Tuple       MsgIPTuple
	Kube        processapi.MsgK8sUnix
	Return      int64
	ProcessKey  processapi.MsgExecveKey
	SockCookie  uint64
	SocketStats MsgSocketStatsUnix
	SocketFlags uint32
}

type Histogram struct {
	B99 uint32
	B90 uint32
	B75 uint32
	B50 uint32
	B25 uint32
	B10 uint32
	B01 uint32
	B00 uint32
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
	Qlen            Histogram
}

type MsgInterface struct {
	Name          string
	Index         int
	Netns         uint64
	ContainerName string
}

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
