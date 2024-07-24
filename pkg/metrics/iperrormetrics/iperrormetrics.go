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
	"github.com/prometheus/client_golang/prometheus"
)

type Error int

const (
	HeaderError Error = iota
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
)

var IpErrorToString = map[Error]string{
	HeaderError:                      "Header error",
	NoHeapAvailable:                  "No heap available",
	ReadIpv6NextFailedKprobe:         "Read IPv6 next failed (probe)",
	ReadIpv6NextFailedSkbLoad:        "Read IPv6 next failed (skb_load)",
	ReadIpv6NextFailedSkb:            "Read IPv6 next failed (skb)",
	UnknownIpv6Extension:             "Unknown IPv6 extension",
	TooManyIpv6Extensions:            "Too many IPv6 extensions",
	UdpStackNoCookie:                 "UDP stack no cookie",
	UdpStackReadVersionFailed:        "UDP stack read version failed",
	UdpStackReadIpHeaderFailed:       "UDP stack read IP header failed",
	UdpStackReadUdpHeaderFailed:      "UDP stack read UDP header failed",
	UdpStackNoPayloadOffset:          "UDP stack no payload offset",
	UdpStackInvalidIpVersion:         "UDP stack invalid IP version",
	UdpStackBurstNoProcess:           "UDP stack burst no process",
	UdpStackBurstNoPID:               "UDP stack burst no PID",
	UdpStackReadPayloadFailed:        "UDP stack read payload failed",
	UdpSendNoSocketInfo:              "UDP send no socket info",
	UdpSendNoCookie:                  "UDP send no cookie",
	UdpRecvNoCookie:                  "UDP recv no cookie",
	UdpRecvReadIpHeaderFailed:        "UDP recv read IP header failed",
	UdpRecvReadUdpHeaderFailed:       "UDP recv read UDP header failed",
	UdpRecvInvalidIpVersion:          "UDP recv invalid IP version",
	UdpSockCreateNoCookie:            "UDP sock create no cookie",
	UdpSockReleaseNoCookie:           "UDP sock release no cookie",
	UdpFailedToReadIpOption:          "UDP failed to read IP option",
	UdpRetprobeAddFailed:             "UDP retprobe add failed",
	UdpRetprobeDeleteFailed:          "UDP retprobe delete failed",
	UdpSockReleaseNoSock:             "UDP sock release no sock",
	UdpSendMissingProcess:            "UDP send missing process",
	UdpRecvMissingProcess:            "UDP recv missing process",
	UpdateSocketmapNoProcess:         "Update socketmap no process",
	SocketDiscoveryNoProcess:         "Socket discovery no process",
	SocketDiscoveryReadError:         "Socket discovery read error",
	UdpSockCreateNoProcess:           "UDP sock create no process",
	SocketDiscoveryNoSk:              "Socket discovery no sk",
	UdpSockCreatePid0:                "UDP sock create PID=0",
	UdpSequenceCheckReadPayloadFlags: "UDP sequence check read payload flags",
	UdpSequenceCheckReadPayloadData:  "UDP sequence check read payload data",
	TcpAcceptRetMissingProcess:       "TCP accept return missing process",
	TcpAcceptRetNoCookie:             "TCP accept return no cookie",
	TcpAcceptNoCookie:                "TCP accept no cookie",
	TcpAcceptNoSocket:                "TCP accept no socket",
	TcpCloseNoSocket:                 "TCP close no socket",
	TcpConnectNoProcess:              "TCP connect no process",
	TcpListenNoProcess:               "TCP listen no process",
	TcpTimestampNoSocket:             "TCP timestamp no socket",
	TcpSendNoCookie:                  "TCP send no cookie",
	TcpSendNoIpHeader:                "TCP send no IP header",
	TcpSendNoSocket:                  "TCP send no socket",
	TcpSendNoSk:                      "TCP send no sk",
	TcpSendNoTcpSock:                 "TCP send no TCP socket",
	TcpRecvNoCookie:                  "TCP recv no cookie",
	TcpRecvNoIpHeader:                "TCP recv no IP header",
	TcpRttNoSocket:                   "TCP RTT no socket",
	TcpRttEqualsZero:                 "TCP RTT equals zero",
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

	for _, error := range IpErrorToString {
		for _, version := range networkapi.IPFamilies {
			ProcessIpErrors(error, version).Add(0)
		}
	}
}

func ProcessIpErrors(err string, version string) prometheus.Counter {
	return processIpErrors.WithLabelValues(err, version)
}
