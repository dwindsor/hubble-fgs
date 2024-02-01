//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package eventmetrics

import (
	"strconv"
	"strings"

	"github.com/cilium/tetragon/api/v1/tetragon"
	oss "github.com/cilium/tetragon/pkg/metrics/eventmetrics"
	"github.com/isovalent/hubble-fgs/pkg/sensors/tcp/tcpconfig"
	"github.com/isovalent/hubble-fgs/pkg/sensors/udp/udpconfig"
)

type SocketLabels struct {
	Ns          string
	Workload    string
	Pod         string
	Binary      string
	DstNs       string
	DstWorkload string
	DstPod      string
	DstDNS      string
	DstIp       string
}

func (s SocketLabels) LabelString() []string {
	return []string{s.Ns, s.Workload, s.Pod, s.Binary, s.DstNs, s.DstWorkload, s.DstPod, s.DstDNS, s.DstIp}
}

func createTCPSocketLabels(res *tetragon.ProcessSockStats) *SocketLabels {
	b, p, w, ns := oss.GetProcessInfo(res.Process)
	dstPod := res.Socket.GetDestinationPod()
	dstPodString, dstWorkload, dstns := GetDstPodInfo(dstPod)
	dstDNS := strings.Join(res.Socket.DestinationNames, ",")
	dstIp := res.Socket.DestinationIp

	if !tcpconfig.CurrentLabels["ns"] {
		ns = ""
	}
	if !tcpconfig.CurrentLabels["workload"] {
		w = ""
	}
	if !tcpconfig.CurrentLabels["pod"] {
		p = ""
	}
	if !tcpconfig.CurrentLabels["binary"] {
		b = ""
	}
	if !tcpconfig.CurrentLabels["dstns"] {
		dstns = ""
	}
	if !tcpconfig.CurrentLabels["dstworkload"] {
		dstWorkload = ""
	}
	if !tcpconfig.CurrentLabels["dstpod"] {
		dstPodString = ""
	}
	if !tcpconfig.CurrentLabels["dstdns"] {
		dstDNS = ""
	}
	if !tcpconfig.CurrentLabels["dstip"] {
		dstIp = ""
	}

	return &SocketLabels{
		Ns:          ns,
		Workload:    w,
		Pod:         p,
		Binary:      b,
		DstNs:       dstns,
		DstWorkload: dstWorkload,
		DstPod:      dstPodString,
		DstDNS:      dstDNS,
		DstIp:       dstIp,
	}
}

func createUDPSocketLabels(res *tetragon.ProcessSockStats) *SocketLabels {
	b, p, w, ns := oss.GetProcessInfo(res.Process)
	dstPod := res.Socket.GetDestinationPod()
	dstPodString, dstWorkload, dstns := GetDstPodInfo(dstPod)
	dstDNS := strings.Join(res.Socket.DestinationNames, ",")
	dstIp := res.Socket.DestinationIp

	if !udpconfig.CurrentLabels["ns"] {
		ns = ""
	}
	if !udpconfig.CurrentLabels["workload"] {
		w = ""
	}
	if !udpconfig.CurrentLabels["pod"] {
		p = ""
	}
	if !udpconfig.CurrentLabels["binary"] {
		b = ""
	}
	if !udpconfig.CurrentLabels["dstns"] {
		dstns = ""
	}
	if !udpconfig.CurrentLabels["dstworkload"] {
		dstWorkload = ""
	}
	if !udpconfig.CurrentLabels["dstpod"] {
		dstPodString = ""
	}
	if !udpconfig.CurrentLabels["dstdns"] {
		dstDNS = ""
	}
	if !udpconfig.CurrentLabels["dstip"] {
		dstIp = ""
	}

	return &SocketLabels{
		Ns:          ns,
		Workload:    w,
		Pod:         p,
		Binary:      b,
		DstNs:       dstns,
		DstWorkload: dstWorkload,
		DstPod:      dstPodString,
		DstDNS:      dstDNS,
		DstIp:       dstIp,
	}
}

type MulticastSocketLabels struct {
	Ns          string
	Workload    string
	Pod         string
	Binary      string
	SrcMcast    string
	DstNs       string
	DstWorkload string
	DstPod      string
	DstMcast    string
}

func createMulticastSocketLabels(res *tetragon.ProcessSockStats) *MulticastSocketLabels {
	b, p, w, ns := oss.GetProcessInfo(res.Process)
	dstPod := res.Socket.GetDestinationPod()
	dstPodString, dstWorkload, dstns := GetDstPodInfo(dstPod)
	sourceIP := res.Socket.SourceIp
	dstIP := res.Socket.DestinationIp

	if !udpconfig.CurrentLabels["ns"] {
		ns = ""
	}
	if !udpconfig.CurrentLabels["workload"] {
		w = ""
	}
	if !udpconfig.CurrentLabels["pod"] {
		p = ""
	}
	if !udpconfig.CurrentLabels["binary"] {
		b = ""
	}
	if !udpconfig.CurrentLabels["dstns"] {
		dstns = ""
	}
	if !udpconfig.CurrentLabels["dstworkload"] {
		dstWorkload = ""
	}
	if !udpconfig.CurrentLabels["dstpod"] {
		dstPodString = ""
	}
	if !udpconfig.CurrentLabels["srcmcast"] {
		sourceIP = ""
	}
	if !udpconfig.CurrentLabels["dstmcast"] {
		dstIP = ""
	}

	return &MulticastSocketLabels{
		Ns:          ns,
		Workload:    w,
		Pod:         p,
		Binary:      b,
		SrcMcast:    sourceIP,
		DstNs:       dstns,
		DstWorkload: dstWorkload,
		DstPod:      dstPodString,
		DstMcast:    dstIP,
	}
}

func (s MulticastSocketLabels) labelString() []string {
	return []string{s.Ns, s.Workload, s.Pod, s.Binary, s.SrcMcast, s.DstNs, s.DstWorkload, s.DstPod, s.DstMcast}
}

type SrcSocketLabels struct {
	Ns       string
	Workload string
	Pod      string
	Binary   string
}

func createTCPSrcSocketLabels(res *tetragon.Process) *SrcSocketLabels {
	b, p, w, ns := oss.GetProcessInfo(res)

	if !tcpconfig.CurrentLabels["ns"] {
		ns = ""
	}
	if !tcpconfig.CurrentLabels["workload"] {
		w = ""
	}
	if !tcpconfig.CurrentLabels["pod"] {
		p = ""
	}
	if !tcpconfig.CurrentLabels["binary"] {
		b = ""
	}

	return &SrcSocketLabels{
		Ns:       ns,
		Workload: w,
		Pod:      p,
		Binary:   b,
	}
}

func createUDPSrcSocketLabels(res *tetragon.Process) *SrcSocketLabels {
	b, p, w, ns := oss.GetProcessInfo(res)

	if !udpconfig.CurrentLabels["ns"] {
		ns = ""
	}
	if !udpconfig.CurrentLabels["Workload"] {
		w = ""
	}
	if !udpconfig.CurrentLabels["pod"] {
		p = ""
	}
	if !udpconfig.CurrentLabels["binary"] {
		b = ""
	}

	return &SrcSocketLabels{
		Ns:       ns,
		Workload: w,
		Pod:      p,
		Binary:   b,
	}
}

func createSrcSocketLabels(res *tetragon.Process) *SrcSocketLabels {
	b, p, w, ns := oss.GetProcessInfo(res)

	return &SrcSocketLabels{
		Ns:       ns,
		Workload: w,
		Pod:      p,
		Binary:   b,
	}
}

func (s SrcSocketLabels) labelString() []string {
	return []string{s.Ns, s.Workload, s.Pod, s.Binary}
}

func GetPromBucket(min, max, upperLimitPercent uint32) string {
	if upperLimitPercent == 100 {
		return "+Inf"
	}
	return strconv.Itoa(int(min + (max-min)*upperLimitPercent/100))
}

func getTcpRttPromBucket(upperLimitPercent uint32) string {
	return GetPromBucket(tcpconfig.RttHistogramMin, tcpconfig.RttHistogramMax, upperLimitPercent)
}

func GetDstPodInfo(dstPod *tetragon.Pod) (pod, workload, ns string) {
	if dstPod != nil {
		ns = dstPod.Namespace
		workload = dstPod.Workload
		pod = dstPod.Name
	}
	return pod, workload, ns
}
