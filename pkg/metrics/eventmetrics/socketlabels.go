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

type socketLabels struct {
	ns          string
	workload    string
	pod         string
	binary      string
	dstns       string
	dstWorkload string
	dstPod      string
	dstDNS      string
}

func (s socketLabels) labelString() []string {
	return []string{s.ns, s.workload, s.pod, s.binary, s.dstns, s.dstWorkload, s.dstPod, s.dstDNS}
}

func createTCPSocketLabels(res *tetragon.ProcessSockStats) *socketLabels {
	b, p, w, ns := oss.GetProcessInfo(res.Process)
	dstPod := res.Socket.GetDestinationPod()
	dstPodString, dstWorkload, dstns := GetDstPodInfo(dstPod)
	dstDNS := strings.Join(res.Socket.DestinationNames, ",")

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

	return &socketLabels{
		ns:          ns,
		workload:    w,
		pod:         p,
		binary:      b,
		dstns:       dstns,
		dstWorkload: dstWorkload,
		dstPod:      dstPodString,
		dstDNS:      dstDNS,
	}
}

func createUDPSocketLabels(res *tetragon.ProcessSockStats) *socketLabels {
	b, p, w, ns := oss.GetProcessInfo(res.Process)
	dstPod := res.Socket.GetDestinationPod()
	dstPodString, dstWorkload, dstns := GetDstPodInfo(dstPod)
	dstDNS := strings.Join(res.Socket.DestinationNames, ",")

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

	return &socketLabels{
		ns:          ns,
		workload:    w,
		pod:         p,
		binary:      b,
		dstns:       dstns,
		dstWorkload: dstWorkload,
		dstPod:      dstPodString,
		dstDNS:      dstDNS,
	}
}

type multicastSocketLabels struct {
	ns          string
	workload    string
	pod         string
	binary      string
	source      string
	dstns       string
	dstWorkload string
	dstPod      string
	dest        string
}

func createMulticastSocketLabels(res *tetragon.ProcessSockStats) *multicastSocketLabels {
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
	if !udpconfig.CurrentLabels["sourceip"] {
		sourceIP = ""
	}
	if !udpconfig.CurrentLabels["dstIP"] {
		dstIP = ""
	}

	return &multicastSocketLabels{
		ns:          ns,
		workload:    w,
		pod:         p,
		binary:      b,
		source:      sourceIP,
		dstns:       dstns,
		dstWorkload: dstWorkload,
		dstPod:      dstPodString,
		dest:        dstIP,
	}
}

func (s multicastSocketLabels) labelString() []string {
	return []string{s.ns, s.workload, s.pod, s.binary, s.source, s.dstns, s.dstWorkload, s.dstPod, s.dest}
}

type srcSocketLabels struct {
	ns       string
	workload string
	pod      string
	binary   string
}

func createTCPSrcSocketLabels(res *tetragon.Process) *srcSocketLabels {
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

	return &srcSocketLabels{
		ns:       ns,
		workload: w,
		pod:      p,
		binary:   b,
	}
}

func createUDPSrcSocketLabels(res *tetragon.Process) *srcSocketLabels {
	b, p, w, ns := oss.GetProcessInfo(res)

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

	return &srcSocketLabels{
		ns:       ns,
		workload: w,
		pod:      p,
		binary:   b,
	}
}

func createSrcSocketLabels(res *tetragon.Process) *srcSocketLabels {
	b, p, w, ns := oss.GetProcessInfo(res)

	return &srcSocketLabels{
		ns:       ns,
		workload: w,
		pod:      p,
		binary:   b,
	}
}

func (s srcSocketLabels) labelString() []string {
	return []string{s.ns, s.workload, s.pod, s.binary}
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
