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
	"github.com/cilium/tetragon/pkg/metrics"
	oss "github.com/cilium/tetragon/pkg/metrics/eventmetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/socketmetrics"
	"github.com/isovalent/hubble-fgs/pkg/sensors/rawsock/rawsockconfig"
	"github.com/isovalent/hubble-fgs/pkg/sensors/tcp/tcpconfig"
	"github.com/isovalent/hubble-fgs/pkg/sensors/udp/udpconfig"
)

func createTCPSocketLabels(res *tetragon.ProcessSockStats) *socketmetrics.SocketLabels {
	b, p, w, ns := oss.GetProcessInfo(res.Process)
	dstPod := res.Socket.GetDestinationPod()
	dstPodString, dstWorkload, dstns := GetDstPodInfo(dstPod)
	dstDNS := strings.Join(res.Socket.DestinationNames, ",")
	dstIp := res.Socket.DestinationIp

	if !tcpconfig.CurrentLabels["namespace"] {
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
	if !tcpconfig.CurrentLabels["dstnamespace"] {
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

	return socketmetrics.NewSocketLabels(ns, w, p, b, dstns, dstWorkload, dstPodString, dstDNS, dstIp)
}

func createUDPSocketLabels(res *tetragon.ProcessSockStats) *socketmetrics.SocketLabels {
	b, p, w, ns := oss.GetProcessInfo(res.Process)
	dstPod := res.Socket.GetDestinationPod()
	dstPodString, dstWorkload, dstns := GetDstPodInfo(dstPod)
	dstDNS := strings.Join(res.Socket.DestinationNames, ",")
	dstIp := res.Socket.DestinationIp

	if !udpconfig.CurrentLabels["namespace"] {
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
	if !udpconfig.CurrentLabels["dstnamespace"] {
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

	return socketmetrics.NewSocketLabels(ns, w, p, b, dstns, dstWorkload, dstPodString, dstDNS, dstIp)
}

func createMulticastSocketLabels(res *tetragon.ProcessSockStats) *socketmetrics.MulticastSocketLabels {
	b, p, w, ns := oss.GetProcessInfo(res.Process)
	dstPod := res.Socket.GetDestinationPod()
	dstPodString, dstWorkload, dstns := GetDstPodInfo(dstPod)
	sourceIP := res.Socket.SourceIp
	dstIP := res.Socket.DestinationIp

	if !udpconfig.CurrentLabels["namespace"] {
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
	if !udpconfig.CurrentLabels["dstnamespace"] {
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

	return socketmetrics.NewMulticastSocketLabels(ns, w, p, b, sourceIP, dstns, dstWorkload, dstPodString, dstIP)
}

func createTCPSrcSocketLabels(res *tetragon.Process) *metrics.ProcessLabels {
	b, p, w, ns := oss.GetProcessInfo(res)

	if !tcpconfig.CurrentLabels["namespace"] {
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

	return metrics.NewProcessLabels(ns, w, p, b)
}

func createUDPSrcSocketLabels(res *tetragon.Process) *metrics.ProcessLabels {
	b, p, w, ns := oss.GetProcessInfo(res)

	if !udpconfig.CurrentLabels["namespace"] {
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

	return metrics.NewProcessLabels(ns, w, p, b)
}

func createRawSocketLabels(res *tetragon.Process) *metrics.ProcessLabels {
	b, p, w, ns := oss.GetProcessInfo(res)

	if !rawsockconfig.CurrentLabels["namespace"] {
		ns = ""
	}
	if !rawsockconfig.CurrentLabels["workload"] {
		w = ""
	}
	if !rawsockconfig.CurrentLabels["pod"] {
		p = ""
	}
	if !rawsockconfig.CurrentLabels["binary"] {
		b = ""
	}

	return metrics.NewProcessLabels(ns, w, p, b)
}

func getPromBucket(min, max, upperLimitPercent uint32) string {
	if upperLimitPercent == 100 {
		return "+Inf"
	}
	return strconv.Itoa(int(min + (max-min)*upperLimitPercent/100))
}

func getTcpRttPromBucket(upperLimitPercent uint32) string {
	return getPromBucket(tcpconfig.RttHistogramMin, tcpconfig.RttHistogramMax, upperLimitPercent)
}

func GetDstPodInfo(dstPod *tetragon.Pod) (pod, workload, ns string) {
	if dstPod != nil {
		ns = dstPod.Namespace
		workload = dstPod.Workload
		pod = dstPod.Name
	}
	return pod, workload, ns
}
