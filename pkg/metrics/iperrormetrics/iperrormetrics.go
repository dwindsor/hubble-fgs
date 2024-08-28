//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package iperrormetrics

import (
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/prometheus/client_golang/prometheus"
)

type IpError int

const (
	HeaderError IpError = iota
	NoHeapAvailable
	ReadIpv6NextFailedKprobe
	ReadIpv6NextFailedSkbLoad
	ReadIpv6NextFailedSkb
	UnknownIpv6Extension
	TooManyIpv6Extensions
	UdpStackNoCookie
	UdpStackReadVersionFailed
	UdpStackReadIpHeaderFailed
	UdpStackReadUdpHeaderFailed
	UdpStackNoPayloadOffset
	UdpStackInvalidIpVersion
	UdpStackBurstNoProcess
	UdpStackBurstNoPID
	UdpStackReadPayloadFailed
	UdpSendNoSocketInfo
	UdpSendNoCookie
	UdpRecvNoCookie
	UdpRecvReadIpHeaderFailed
	UdpRecvReadUdpHeaderFailed
	UdpRecvInvalidIpVersion
	UdpSockCreateNoCookie
	UdpSockReleaseNoCookie
	UdpFailedToReadIpOption
	UdpRetprobeAddFailed
	UdpRetprobeDeleteFailed
	UdpSockReleaseNoSock
	UdpSendMissingProcess
	UdpRecvMissingProcess
	UpdateSocketmapNoProcess
	SocketDiscoveryNoProcess
	SocketDiscoveryReadError
	UdpSockCreateNoProcess
	SocketDiscoveryNoSk
	UdpSockCreatePid0
	UdpSequenceCheckReadPayloadFlags
	UdpSequenceCheckReadPayloadData
	TcpAcceptRetMissingProcess
	TcpAcceptRetNoCookie
	TcpAcceptNoCookie
	TcpAcceptNoSocket
	TcpCloseNoSocket
	TcpConnectNoProcess
	TcpListenNoProcess
	TcpTimestampNoSocket
	TcpSendNoCookie
	TcpSendNoIpHeader
	TcpSendNoSocket
	TcpSendNoSk
	TcpSendNoTcpSock
	TcpRecvNoCookie
	TcpRecvNoIpHeader
	TcpRttNoSocket
	TcpRttEqualsZero
	TcpRttCannotReadRxOpt
	TcpRttNoTimestamp
	TcpRttDeltaTooBig
)

type Protocol int

const (
	Unknown Protocol = iota
	Tcp
	Udp
	Ipv6
	SocketDiscovery
)

var ProtocolToString = map[Protocol]string{
	Unknown:         "unknown",
	Tcp:             "tcp",
	Udp:             "udp",
	Ipv6:            "ipv6",
	SocketDiscovery: "socketdiscovery",
}

type Config struct {
	Msg      string
	Protocol Protocol
}

var IpErrorToString = map[IpError]Config{
	HeaderError:                      {Msg: "Header error", Protocol: Ipv6},
	NoHeapAvailable:                  {Msg: "No heap available", Protocol: Ipv6},
	ReadIpv6NextFailedKprobe:         {Msg: "Read IPv6 next failed (probe)", Protocol: Ipv6},
	ReadIpv6NextFailedSkbLoad:        {Msg: "Read IPv6 next failed (skb_load)", Protocol: Ipv6},
	ReadIpv6NextFailedSkb:            {Msg: "Read IPv6 next failed (skb)", Protocol: Ipv6},
	UnknownIpv6Extension:             {Msg: "Unknown IPv6 extension", Protocol: Ipv6},
	TooManyIpv6Extensions:            {Msg: "Too many IPv6 extensions", Protocol: Ipv6},
	UdpStackNoCookie:                 {Msg: "UDP stack no cookie", Protocol: Udp},
	UdpStackReadVersionFailed:        {Msg: "UDP stack read version failed", Protocol: Udp},
	UdpStackReadIpHeaderFailed:       {Msg: "UDP stack read IP header failed", Protocol: Udp},
	UdpStackReadUdpHeaderFailed:      {Msg: "UDP stack read UDP header failed", Protocol: Udp},
	UdpStackNoPayloadOffset:          {Msg: "UDP stack no payload offset", Protocol: Udp},
	UdpStackInvalidIpVersion:         {Msg: "UDP stack invalid IP version", Protocol: Udp},
	UdpStackBurstNoProcess:           {Msg: "UDP stack burst no process", Protocol: Udp},
	UdpStackBurstNoPID:               {Msg: "UDP stack burst no PID", Protocol: Udp},
	UdpStackReadPayloadFailed:        {Msg: "UDP stack read payload failed", Protocol: Udp},
	UdpSendNoSocketInfo:              {Msg: "UDP send no socket info", Protocol: Udp},
	UdpSendNoCookie:                  {Msg: "UDP send no cookie", Protocol: Udp},
	UdpRecvNoCookie:                  {Msg: "UDP recv no cookie", Protocol: Udp},
	UdpRecvReadIpHeaderFailed:        {Msg: "UDP recv read IP header failed", Protocol: Udp},
	UdpRecvReadUdpHeaderFailed:       {Msg: "UDP recv read UDP header failed", Protocol: Udp},
	UdpRecvInvalidIpVersion:          {Msg: "UDP recv invalid IP version", Protocol: Udp},
	UdpSockCreateNoCookie:            {Msg: "UDP sock create no cookie", Protocol: Udp},
	UdpSockReleaseNoCookie:           {Msg: "UDP sock release no cookie", Protocol: Udp},
	UdpFailedToReadIpOption:          {Msg: "UDP failed to read IP option", Protocol: Udp},
	UdpRetprobeAddFailed:             {Msg: "UDP retprobe add failed", Protocol: Udp},
	UdpRetprobeDeleteFailed:          {Msg: "UDP retprobe delete failed", Protocol: Udp},
	UdpSockReleaseNoSock:             {Msg: "UDP sock release no sock", Protocol: Udp},
	UdpSendMissingProcess:            {Msg: "UDP send missing process", Protocol: Udp},
	UdpRecvMissingProcess:            {Msg: "UDP recv missing process", Protocol: Udp},
	UpdateSocketmapNoProcess:         {Msg: "Update socketmap no process", Protocol: Udp},
	SocketDiscoveryNoProcess:         {Msg: "Socket discovery no process", Protocol: SocketDiscovery},
	SocketDiscoveryReadError:         {Msg: "Socket discovery read error", Protocol: SocketDiscovery},
	UdpSockCreateNoProcess:           {Msg: "UDP sock create no process", Protocol: Udp},
	SocketDiscoveryNoSk:              {Msg: "Socket discovery no sk", Protocol: SocketDiscovery},
	UdpSockCreatePid0:                {Msg: "UDP sock create PID=0", Protocol: Udp},
	UdpSequenceCheckReadPayloadFlags: {Msg: "UDP sequence check read payload flags", Protocol: Udp},
	UdpSequenceCheckReadPayloadData:  {Msg: "UDP sequence check read payload data", Protocol: Udp},
	TcpAcceptRetMissingProcess:       {Msg: "TCP accept return missing process", Protocol: Tcp},
	TcpAcceptRetNoCookie:             {Msg: "TCP accept return no cookie", Protocol: Tcp},
	TcpAcceptNoCookie:                {Msg: "TCP accept no cookie", Protocol: Tcp},
	TcpAcceptNoSocket:                {Msg: "TCP accept no socket", Protocol: Tcp},
	TcpCloseNoSocket:                 {Msg: "TCP close no socket", Protocol: Tcp},
	TcpConnectNoProcess:              {Msg: "TCP connect no process", Protocol: Tcp},
	TcpListenNoProcess:               {Msg: "TCP listen no process", Protocol: Tcp},
	TcpTimestampNoSocket:             {Msg: "TCP timestamp no socket", Protocol: Tcp},
	TcpSendNoCookie:                  {Msg: "TCP send no cookie", Protocol: Tcp},
	TcpSendNoIpHeader:                {Msg: "TCP send no IP header", Protocol: Tcp},
	TcpSendNoSocket:                  {Msg: "TCP send no socket", Protocol: Tcp},
	TcpSendNoSk:                      {Msg: "TCP send no sk", Protocol: Tcp},
	TcpSendNoTcpSock:                 {Msg: "TCP send no TCP socket", Protocol: Tcp},
	TcpRecvNoCookie:                  {Msg: "TCP recv no cookie", Protocol: Tcp},
	TcpRecvNoIpHeader:                {Msg: "TCP recv no IP header", Protocol: Tcp},
	TcpRttNoSocket:                   {Msg: "TCP RTT no socket", Protocol: Tcp},
	TcpRttEqualsZero:                 {Msg: "TCP RTT equals zero", Protocol: Tcp},
	TcpRttCannotReadRxOpt:            {Msg: "TCP RTT cannot read rx_opt", Protocol: Tcp},
	TcpRttNoTimestamp:                {Msg: "TCP RTT no timestamp", Protocol: Tcp},
	TcpRttDeltaTooBig:                {Msg: "TCP RTT delta too big", Protocol: Tcp},
}

var (
	processIpErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "layer3_event_errors_total",
		Namespace: consts.MetricsNamespace,
		Help:      "Errors propagated to userspace by the L3 event sensors",
	}, []string{"error", "version"})
)

func InitMetrics(registry *prometheus.Registry) {
	registry.MustRegister(processIpErrors)

	for _, errorStr := range IpErrorToString {
		for _, version := range networkapi.IPFamilies {
			ProcessIpErrors(errorStr.Msg, version).Add(0)
		}
	}
}

func ProcessIpErrors(err string, version string) prometheus.Counter {
	return processIpErrors.WithLabelValues(err, version)
}

func ProtoEnabled(proto Protocol) bool {
	pstr, ok := ProtocolToString[proto]
	if !ok {
		return false
	}
	for _, p := range option.Config.DebugX {
		if pstr == p || pstr+"+" == p {
			return true
		}
	}
	return false
}

func ProtoConsoleEnabled(proto Protocol) bool {
	pstr, ok := ProtocolToString[proto]
	if !ok {
		return false
	}
	for _, p := range option.Config.DebugX {
		if pstr+"+" == p {
			return true
		}
	}
	return false
}
