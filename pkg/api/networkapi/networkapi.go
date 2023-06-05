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

type MsgIPTuple struct {
	SAddr [2]uint64
	DAddr [2]uint64
	DPort uint16
	SPort uint16
	Proto uint8
	Pad   [3]uint8
	// define as uint8 otherwise padding in struct breaks
	PostData [6]uint8
	Pad2     [2]uint8
	IPv6     uint8
	Pad3     [7]uint8
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
	Duration    uint64                  `align:"duration"`
}

type MsgSocketStatsUnix struct {
	Ktime            uint64
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
	Latency          Histogram
	Rtt              Histogram
}

type MsgSocketStats struct {
	Ktime            uint64
	BytesSent        uint64
	BytesReceived    uint64
	SegsIn           uint32
	SegsOut          uint32
	BytesSubmitted   uint64
	BytesConsumed    uint64
	SegsConsumed     uint32
	SegsSubmitted    uint32
	SRtt             uint32
	RetransmitSegs   uint32
	RetransmitBytes  uint64
	ToZeroWindow     uint32
	SkDrop           uint32
	SkbConsumeMisses uint32
	Pad              uint32
	RttBuckets       [8]uint64
	LatencyBuckets   [8]uint64
	RttSum           uint64
	LatencySum       uint64
}

type Histogram struct {
	B99 uint64
	B90 uint64
	B75 uint64
	B50 uint64
	B25 uint64
	B10 uint64
	B01 uint64
	B00 uint64
	Sum uint64
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

type MsgProcessNetworkWatermarkEvent struct {
	Common           processapi.MsgCommon
	ProcessKey       processapi.MsgExecveKey
	Protocol         uint32 // IP protocol
	Direction        uint8  // ingress = 0, egress = 1
	State            uint8  // end = 0, start = 1
	Type             uint8  // burst = 0, dip = 1
	Pad              uint8
	WindowSize       uint64 // Nanoseconds
	HistAvg          uint64 // Bytes per WindowSize
	HistBurstTrigger uint64 // Bytes per WindowSize burst trigger level
	HistDipTrigger   uint64 // Bytes per WindowSize dip trigger level
	WindowAvg        uint64 // Bytes seen in WindowSize
}

type MsgUdpSeqCheckErrorEvent struct {
	Common         processapi.MsgCommon
	ProcessKey     processapi.MsgExecveKey
	Tuple          MsgIPTuple
	SockCookie     uint64
	ApplicationId  uint64
	AppSpecificId  uint64
	SeqNumExpected uint64
	SeqNumReceived uint64
}

type MsgProcessNetworkWatermarksEventUnix = MsgProcessNetworkWatermarkEvent
