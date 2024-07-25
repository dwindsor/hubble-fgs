package networkapi

import (
	"encoding/binary"
	"fmt"
	"net"

	corev1 "k8s.io/api/core/v1"

	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
)

const (
	IPv4Family = string(corev1.IPv4Protocol)
	IPv6Family = string(corev1.IPv6Protocol)
)

var IPFamilies = []string{
	IPv4Family,
	IPv6Family,
}

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
	SAddr       [2]uint64
	DAddr       [2]uint64
	DPort       uint16
	SPort       uint16
	Proto       uint8
	Send        uint8
	VersionByte uint8
	IPv6        uint8
	// define as uint8 otherwise padding in struct breaks
	PostData [6]uint8
	Pad      uint16
}

type MsgSocketId struct {
	Cookie  uint64
	Version uint32
}

func (m *MsgIPTuple) GetPostDAddr() uint32 {
	return binary.LittleEndian.Uint32(m.PostData[0:4])
}

func (m *MsgIPTuple) GetPostDPort() uint16 {
	return binary.LittleEndian.Uint16(m.PostData[4:6])
}

func GetIPv4(i uint32, op uint8) net.IP {
	if op == ops.MSG_OP_BIND {
		return net.IPv4zero
	}
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, i)
	return ip
}

func GetIP(i [2]uint64, op uint8, ipv6 bool) net.IP {
	if !ipv6 {
		return GetIPv4(uint32(i[0]), op)
	}
	if op == ops.MSG_OP_BIND {
		return net.IPv6zero
	}
	a := make([]byte, 8)
	b := make([]byte, 8)

	binary.LittleEndian.PutUint64(a, i[0])
	binary.LittleEndian.PutUint64(b, i[1])
	ip := append(a, b...)
	return ip
}

// Ports are stored in host order.
func GetDport(dport uint16, op uint8) uint16 {
	if op == ops.MSG_OP_BIND || op == ops.MSG_OP_LISTEN {
		return 0
	}
	return dport
}

func GetSport(sport uint16) uint16 {
	return sport
}

func SwapByte(b uint16) uint16 {
	return (b << 8) | (b >> 8)
}

// TupleAddrString returns two strings to represent the tuple addresses.
// The first is the source, and the second is the destination.
func TupleAddrString(tuple *MsgIPTuple, op uint8) (string, string) {
	var saddr, daddr net.IP
	var sport, dport uint16

	saddr = GetIP(tuple.SAddr, op, tuple.IPv6 == 1)
	daddr = GetIP(tuple.DAddr, op, tuple.IPv6 == 1)

	sport = tuple.SPort
	dport = GetDport(tuple.DPort, op)

	wrapAddr := func(ip net.IP) string {
		if tuple.IPv6 == 1 {
			return fmt.Sprintf("[%s]", ip)
		}
		return fmt.Sprint(ip)
	}

	return fmt.Sprintf("%s:%d", wrapAddr(saddr), sport), fmt.Sprintf("%s:%d", wrapAddr(daddr), dport)
}

func (m *MsgIPTuple) String() string {
	source, dest := TupleAddrString(m, ops.MSG_OP_TCPSTATS)
	return fmt.Sprintf("%s -> %s", source, dest)
}

type MsgIPEvent struct {
	Common      processapi.MsgCommon    `align:"common"`
	Tuple       MsgIPTuple              `align:"tuple"`
	Return      int64                   `align:"ret"`
	ProcessKey  processapi.MsgExecveKey `align:"key"`
	SockCookie  uint64                  `align:"socket_cookie"`
	SocketFlags uint32                  `align:"socket_flags"`
	Version     uint32                  `align:"version"`
	CreateTime  uint64                  `align:"create_time"`
	CloseTime   uint64                  `align:"close_time"`
}

type MsgIPWithStatsEvent struct {
	MsgIPEvent
	SocketStats MsgSocketStats `align:"stats"`
}

type MsgICMPData struct {
	IcmpType      uint8
	IcmpCode      uint8
	IcmpData      [4]uint8
	IcmpLen       uint16
	IcmpIpProto   uint8
	IcmpIpTtl     uint8
	IcmpIpPort    uint16
	IcmpIpPointer uint32
	IcmpGateway   [2]uint64
}

type MsgICMPEvent struct {
	Common     processapi.MsgCommon    `align:"common"`
	Tuple      MsgIPTuple              `align:"tuple"`
	ProcessKey processapi.MsgExecveKey `align:"key"`
	SockCookie uint64                  `align:"socket_cookie"`
	IcmpData   MsgICMPData
}

func (m *MsgSocketStats) String() string {
	type _MsgSocketStats MsgSocketStats

	return fmt.Sprintf("%+v", _MsgSocketStats(*m))
}

type MsgSocketStats struct {
	Ktime            uint64
	CreateKtime      uint64
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
	Rtt              Histogram
	Latency          Histogram
}

type Histogram struct {
	B00 uint64
	B01 uint64
	B10 uint64
	B25 uint64
	B50 uint64
	B75 uint64
	B90 uint64
	B99 uint64
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
