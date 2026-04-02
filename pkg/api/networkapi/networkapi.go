// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

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
	// Extra flags
	SOCKFLAGS_CONNECT_FAILED   = 0x10000
	SOCKFLAGS_CONNECTION_RESET = 0x20000
)

const (
	// MsgUnixSize of burst msg
	MsgUnixSize uint32 = 640
)

type MsgIPTuple struct {
	SAddr       [2]uint64 `align:"saddr"`
	DAddr       [2]uint64 `align:"daddr"`
	DPort       uint16    `align:"dport"`
	SPort       uint16    `align:"sport"`
	Proto       uint8     `align:"proto"`
	Send        uint8     `align:"send"`
	VersionByte uint8     `align:"version_byte"`
	IPv6        uint8     `align:"ipv6"`
	ConnId      uint64    `align:"conn_id"`
}

type MsgSocketId struct {
	Cookie  uint64
	Version uint64
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
	PsVersion   uint64                  `align:"ps_version"`
	CreateTime  uint64                  `align:"create_time"`
	CloseTime   uint64                  `align:"close_time"`
}

type MsgIPWithTNPEvent struct {
	MsgIPEvent
	PolicyId uint64 `align:"policy_id"`
	RuleId   uint64 `align:"rule_id"`
	Verdict  uint64 `align:"verdict"`
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
	Ktime           uint64    `align:"ktime"`
	CreateTime      uint64    `align:"create_time"`
	BytesSent       uint64    `align:"bytes_sent"`
	BytesReceived   uint64    `align:"bytes_received"`
	SegsIn          uint32    `align:"segs_in"`
	SegsOut         uint32    `align:"segs_out"`
	Srtt            uint32    `align:"srtt"`
	RetransmitSegs  uint32    `align:"retranssegs"`
	RetransmitBytes uint64    `align:"retransbytes"`
	ZeroWindow      uint32    `align:"zero_window"`
	SkDrops         uint32    `align:"sk_drops"`
	Rtt             Histogram `align:"rtt_buckets"`
	Latency         Histogram `align:"latency_buckets"`
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
	WLID   uint64                  `align:"wlid"`
	Self   processapi.MsgExecveKey `align:"self"`
	Parent processapi.MsgExecveKey `align:"parent"`
}

type DestinationEndpointKey struct {
	LocalId       uint64 `align:"local_id"`
	LocalWLID     uint64 `align:"local_wlid"`
	DestinationId uint64 `align:"destination_id"`
	Source        uint64 `align:"source"`
	Port          uint64 `align:"port"`
}

type TcpValue struct {
	Key         processapi.MsgExecveKey `align:"key"`
	DstKey      DestinationEndpointKey  `align:"dst_key"`
	Version     uint64                  `align:"version"`
	Tuple       MsgIPTuple              `align:"tuple"`
	SocketFlags uint32                  `align:"socket_flags"`
	Closed      uint8                   `align:"closed"`
	Deny        uint8                   `align:"deny"`
	Pad         uint16                  `align:"pad"`
	Stats       MsgSocketStats          `align:"stats"`
}

func (t *TcpValue) String() string {
	policy := "Allow"
	if t.Deny > 0 {
		policy = "Deny"
	}
	return fmt.Sprintf("Pid: %d CreateTime %d Last %d Sent (%d:%d) Recv (%d:%d) Zero %d Retransmit (%d:%d) Drops %d Srtt %d Policy: %s",
		t.Key.Pid,
		t.Stats.CreateTime, t.Stats.Ktime,
		t.Stats.BytesSent, t.Stats.SegsOut, t.Stats.BytesReceived, t.Stats.SegsIn,
		t.Stats.ZeroWindow,
		t.Stats.RetransmitBytes, t.Stats.RetransmitSegs,
		t.Stats.SkDrops, t.Stats.Srtt,
		policy)
}

type TCPSockStatValue struct {
	WatermarksEnable           uint8    `align:"watermarksEnable"`
	RTTEnable                  uint8    `align:"rttEnable"`
	Pad                        [6]uint8 `align:"pad"`
	WatermarksAvgWindowSize    uint64   `align:"watermarksAvgWindowSize"`
	WatermarksWindowSizeNs     uint64   `align:"watermarksWindowSizeNs"`
	WatermarksBurstTriggerMult uint64   `align:"watermarksBurstTriggerMult"`
	WatermarksDipTriggerMult   uint64   `align:"watermarksDipTriggerMult"`
	RttBucket0                 uint32   `align:"bucket00"`
	RttBucket1                 uint32   `align:"bucket01"`
	RttBucket2                 uint32   `align:"bucket10"`
	RttBucket3                 uint32   `align:"bucket25"`
	RttBucket4                 uint32   `align:"bucket50"`
	RttBucket5                 uint32   `align:"bucket75"`
	RttBucket6                 uint32   `align:"bucket90"`
	RttBucket7                 uint32   `align:"bucket99"`
}

type TCPEventDisableValue struct {
	DisableConnect uint8    `align:"disableConnect"`
	DisableClose   uint8    `align:"disableClose"`
	DisableAccept  uint8    `align:"disableAccept"`
	DisableListen  uint8    `align:"disableListen"`
	Pad            [4]uint8 `align:"pad"` // Pad to 64bit boundary for sanity.
}

func (v *TCPEventDisableValue) String() string {
	return fmt.Sprintf("DisableConnect: %d, "+
		"DisableClose: %d "+
		"DisableAccept: %d, "+
		"DisableListen: %d, ",
		v.DisableConnect, v.DisableClose, v.DisableAccept, v.DisableListen)
}

type CgroupProtocolConfigValue struct {
	ICMP4Enabled uint32 `align:"icmp4"`
	ICMP6Enabled uint32 `align:"icmp6"`
	TCP4Enabled  uint32 `align:"tcp4"`
	TCP6Enabled  uint32 `align:"tcp6"`
	UDP4Enabled  uint32 `align:"udp4"`
	UDP6Enabled  uint32 `align:"udp6"`
}

func (v *CgroupProtocolConfigValue) String() string {
	return fmt.Sprintf("CgroupProtocolConfigValue: "+
		"icmp4Enabled: %d, "+
		"icmp6Enabled: %d, "+
		"tcp4Enabled: %d, "+
		"tcp6Enabled: %d, "+
		"udp4Enabled: %d, "+
		"udp6Enabled: %d",
		v.ICMP4Enabled,
		v.ICMP6Enabled,
		v.TCP4Enabled,
		v.TCP6Enabled,
		v.UDP4Enabled,
		v.UDP6Enabled,
	)
}

type Layer3ConfigValue struct {
	EnableIcmpTracking uint8                     `align:"icmp_tracking_enabled"`
	IcmpNetMatch       uint8                     `align:"icmp_net_match"`
	RawEnabled         uint8                     `align:"raw_enabled"`
	RawReportClose     uint8                     `align:"raw_report_close"`
	UdpReportClose     uint8                     `align:"udp_report_close"`
	ICMPV6Info         uint8                     `align:"icmp_v6_info"`
	Pad                [2]uint8                  `align:"pad"`
	TCP                TCPSockStatValue          `align:"tcp"`
	TCPDisable         TCPEventDisableValue      `align:"tcp_disable"`
	UDP                UdpConfigValue            `align:"udp"`
	Proto              CgroupProtocolConfigValue `align:"proto"`
}

const (
	UdpMaxDnsPorts       = 4
	UdpMaxMulticastPorts = 8
)

type UdpConfigValue struct {
	DnsPorts                      [UdpMaxDnsPorts]uint16       `align:"dns_ports"`
	DnsStatsPerSocket             uint8                        `align:"dns_stats_per_socket"`
	DnsReportQuestions            uint8                        `align:"dns_report_questions"`
	WatermarksEnable              uint8                        `align:"watermarks_enable"`
	DisableListenEvents           uint8                        `align:"disable_listen_events"`
	DisableConnectEvents          uint8                        `align:"disable_connect_events"`
	DisableCloseEvents            uint8                        `align:"disable_close_events"`
	EnableMulticastSeqCheck       uint8                        `align:"enable_multicast_seq_check"`
	Pad                           uint8                        `align:"pad"`
	WatermarksAvgWindowSizeMs     uint64                       `align:"watermarks_avg_window_size_ms"`
	WatermarksWindowSize          uint64                       `align:"watermarks_window_size"`
	WatermarksBurstTriggerPercent uint64                       `align:"watermarks_burst_trigger_percent"`
	WatermarksDipTriggerPercent   uint64                       `align:"watermarks_dip_trigger_percent"`
	MulticastAppId                uint64                       `align:"multicast_app_id"`
	MulticastPorts                [UdpMaxMulticastPorts]uint16 `align:"multicast_ports"`
	IdleTimeout                   uint64                       `align:"idle_timeout"`
}

func (v *UdpConfigValue) String() string {
	return fmt.Sprintf("dnsPorts: %d, "+
		"dnsStatsPerSocket: %d, "+
		"dnsReportQuestions: %d, "+
		"disableListenEvents: %d, "+
		"disableConnectEvents: %d, "+
		"disableCloseEvents: %d, "+
		"watermarkEnable: %d, "+
		"watermarkAvgWindowSizeMs: %d, "+
		"watermarkWindowSize: %d, "+
		"watermarkBurstTriggerPercent: %d, "+
		"watermarkDipTriggerPercent: %d, "+
		"multicastAppId: %d, "+
		"multicastPorts: %d, "+
		"enableMulticastSeqCheck: %d, "+
		"idleTimeout: %d",
		v.DnsPorts, v.DnsStatsPerSocket, v.DnsReportQuestions,
		v.DisableListenEvents, v.DisableConnectEvents, v.DisableCloseEvents,
		v.WatermarksEnable, v.WatermarksAvgWindowSizeMs, v.WatermarksWindowSize, v.WatermarksBurstTriggerPercent, v.WatermarksDipTriggerPercent,
		v.MulticastAppId, v.MulticastPorts, v.EnableMulticastSeqCheck,
		v.IdleTimeout)
}

type UdpInfoKey struct {
	Cookie  uint64     `align:"cookie"`
	Tuple   MsgIPTuple `align:"tuple"`
	Version uint64     `align:"version"`
}

type UdpInfoValue struct {
	TXBytes    uint64    `align:"tx_bytes"`
	RXBytes    uint64    `align:"rx_bytes"`
	SegsIn     uint64    `align:"segs_in"`
	SegsOut    uint64    `align:"segs_out"`
	Ktime      uint64    `align:"ktime"`
	PidKtime   uint64    `align:"pid_ktime"`
	Pid        uint32    `align:"pid"`
	SkDrops    uint32    `align:"sk_drops"`
	Buckets    [8]uint64 `align:"buckets"`
	LatencySum uint64    `align:"latency_sum"`
	CreateTime uint64    `align:"create_time"`
	PsVersion  uint64    `align:"ps_version"`
}

func (k *UdpInfoKey) String() string {
	ipSrc := GetIP(k.Tuple.SAddr, ops.MSG_OP_UDPCONNECT, k.Tuple.IPv6 != 0)
	ipDst := GetIP(k.Tuple.DAddr, ops.MSG_OP_UDPCONNECT, k.Tuple.IPv6 != 0)
	return fmt.Sprintf("Cookie=%d:%d\n"+
		"SAddr=%s:%d\n"+
		"DAddr=%s:%d\n", k.Version, k.Cookie, ipSrc, k.Tuple.SPort, ipDst, k.Tuple.DPort)
}

func (k *UdpInfoKey) Copy() *UdpInfoKey {
	newKey := &UdpInfoKey{}
	*newKey = *k
	return newKey
}

func (v *UdpInfoValue) String() string {
	return fmt.Sprintf(
		"Pid: %d Ktime %d\n"+
			"TXBytes: %d RXBytes%d\n"+
			"SegsOut: %d SegsIn: %d\n"+
			"SkDrops: %d\n",
		v.Pid, v.Ktime,
		v.TXBytes, v.RXBytes,
		v.SegsOut, v.SegsIn,
		v.SkDrops)
}

func (v *UdpInfoValue) Copy() *UdpInfoValue {
	newValue := &UdpInfoValue{}
	*newValue = *v
	return newValue
}

type FdLookupKey struct {
	Zero uint32
}

type FdLookupValue struct {
	Pid         uint32     `align:"pid"`
	Fd          uint32     `align:"fd"`
	Sockaddr    uint64     `align:"sockaddr"`
	SockVersion uint64     `align:"sockversion"`
	Tuple       MsgIPTuple `align:"tuple"`
	State       uint8      `align:"state"`
	SignalHit   uint8      `align:"signal_hit"`
	Family      uint16     `align:"family"`
	Protocol    uint16     `align:"protocol"`
	Pad         uint16     `align:"pad"`
	CgrpId      uint64     `align:"cgrpid"`
	Hint        uint64     `align:"hint"`
}

func (k *FdLookupKey) String() string { return fmt.Sprintf("key=%d", k.Zero) }

func (v *FdLookupValue) String() string {
	return fmt.Sprintf("value=%d %d", v.Pid, v.Fd)
}
