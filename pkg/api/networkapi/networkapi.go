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
	Version uint64
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
	Pad         uint32                  `align:"pad"`
	Version     uint64                  `align:"version"`
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
	CreateTime       uint64
	BytesSent        uint64
	BytesReceived    uint64
	SegsIn           uint32
	SegsOut          uint32
	Srtt             uint32
	RetransmitSegs   uint32
	RetransmitBytes  uint64
	ZeroWindow       uint32
	SkDrops          uint32
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

type TcpBpfKey struct {
	SockCookie uint64
}

func (k *TcpBpfKey) String() string { return fmt.Sprintf("Cookie: %d", k.SockCookie) }

type TcpKey struct {
	SockCookie uint64
	CreateTime uint64
}

type ProcessTreeKey struct {
	Nsid   uint64                  `align:"nsid"`
	Self   processapi.MsgExecveKey `align:"self"`
	Parent processapi.MsgExecveKey `align:"parent"`
}

type DestinationEndpointKey struct {
	ProcessId     ProcessTreeKey `align:"process_id"`
	DestinationId uint64         `align:"destination_id"`
	Source        uint64         `align:"source"`
	Port          uint64         `align:"port"`
}

type TcpValue struct {
	Key             processapi.MsgExecveKey `align:"key"`
	DstKey          DestinationEndpointKey  `align:"dst_key"`
	CreateTime      uint64                  `align:"create_time"`
	ZeroWindow      uint32                  `align:"zero_window"`
	SocketFlags     uint32                  `align:"socket_flags"`
	Ktime           uint64                  `align:"ktime"`
	BytesSent       uint64                  `align:"bytes_sent"`
	BytesRecv       uint64                  `align:"bytes_received"`
	SegsOut         uint32                  `align:"segs_out"`
	SegsIn          uint32                  `align:"segs_in"`
	RetransmitBytes uint64                  `align:"retransbytes"`
	RetransmitSegs  uint32                  `align:"retranssegs"`
	SkDrops         uint32                  `align:"sk_drops"`
	Version         uint64                  `align:"version"`
	Rtt             Histogram               `align:"rtt_buckets"`
	Latency         Histogram               `align:"latency_buckets"`
	Srtt            uint32                  `align:"srtt"`
	Ipv6            uint8                   `align:"ipv6"`
	FinRx           uint8                   `align:"fin_rx"`
	Protocol        uint8                   `align:"protocol"`
	Closed          uint8                   `align:"closed"`
}

func (t *TcpValue) String() string {
	return fmt.Sprintf("Pid: %d CreateTime %d Last %d Sent (%d:%d) Recv (%d:%d) Zero %d Retransmit (%d:%d) Drops %d Srtt %d",
		t.Key.Pid,
		t.CreateTime, t.Ktime,
		t.BytesSent, t.SegsOut, t.BytesRecv-uint64(t.FinRx), t.SegsIn,
		t.ZeroWindow,
		t.RetransmitBytes, t.RetransmitSegs,
		t.SkDrops, t.Srtt)
}

type UdpInfoKey struct {
	Cookie  uint64     `align:"cookie"`
	Tuple   MsgIPTuple `align:"tuple"`
	Version uint64     `align:"version"`
}

type UdpInfoValue struct {
	TXBytes          uint64    `align:"tx_bytes"`
	RXBytes          uint64    `align:"rx_bytes"`
	SegsIn           uint64    `align:"segs_in"`
	SegsOut          uint64    `align:"segs_out"`
	Ktime            uint64    `align:"ktime"`
	PidKtime         uint64    `align:"pid_ktime"`
	Pid              uint32    `align:"pid"`
	SkDrops          uint32    `align:"sk_drops"`
	SkbConsumeMisses uint32    `align:"skb_consume_misses"`
	Padding          uint32    `align:"padding"`
	Buckets          [8]uint64 `align:"buckets"`
	LatencySum       uint64    `align:"latency_sum"`
	CreateTime       uint64    `align:"create_time"`
}

func (k *UdpInfoKey) String() string {
	ipSrc := GetIP(k.Tuple.SAddr, ops.MSG_OP_UDPCONNECT, k.Tuple.IPv6 != 0)
	ipDst := GetIP(k.Tuple.DAddr, ops.MSG_OP_UDPCONNECT, k.Tuple.IPv6 != 0)
	return fmt.Sprintf("Cookie=%d:%d\n"+
		"SAddr=%s:%d\n"+
		"DAddr=%s:%d\n", k.Version, k.Cookie, ipSrc, k.Tuple.SPort, ipDst, k.Tuple.DPort)
}

func (v *UdpInfoValue) String() string {
	return fmt.Sprintf(
		"Pid: %d Ktime %d\n"+
			"TXBytes: %d RXBytes%d\n"+
			"SegsOut: %d SegsIn: %d\n"+
			"SkDrops: %d\n"+
			"SkbConsumeMisses: %d\n",
		v.Pid, v.Ktime,
		v.TXBytes, v.RXBytes,
		v.SegsOut, v.SegsIn,
		v.SkDrops, v.SkbConsumeMisses)
}
