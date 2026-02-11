// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package eventmetrics

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cilium/tetragon/pkg/metrics"
	oss "github.com/cilium/tetragon/pkg/metrics/eventmetrics"

	"github.com/cilium/tetragon/api/v1/tetragon"

	"github.com/isovalent/hubble-fgs/pkg/metrics/httpmetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/socketmetrics"
	"github.com/isovalent/hubble-fgs/pkg/sensors/http/httpconfig"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/tcpconfig"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/udpconfig"
)

func getPromBucket(minimum, maximum, upperLimitPercent uint32) string {
	if upperLimitPercent == 100 {
		return "+Inf"
	}
	return strconv.Itoa(int(minimum + (maximum-minimum)*upperLimitPercent/100))
}

func getTcpRttPromBucket(upperLimitPercent uint32) string {
	return getPromBucket(tcpconfig.RttHistogramMin, tcpconfig.RttHistogramMax, upperLimitPercent)
}

func getSocketInfo(processLabels *metrics.ProcessLabels, socket *tetragon.SockInfo) *socketmetrics.SocketLabels {
	var dstns, dstworkload, dstpod, dstDNS, dstip string
	if socket != nil {
		dstPod := socket.GetDestinationPod()
		if dstPod != nil {
			dstns = dstPod.Namespace
			dstworkload = dstPod.Workload
			dstpod = dstPod.Name
		}
		dstDNS = strings.Join(socket.DestinationNames, ",")
		dstip = socket.DestinationIp
	}
	return socketmetrics.NewSocketLabels(
		processLabels.Namespace, processLabels.Workload, processLabels.Pod, processLabels.Binary,
		dstns, dstworkload, dstpod, dstDNS, dstip,
	)
}

func createProcessLabels(labelFilter metrics.LabelFilter, res *tetragon.Process) *metrics.ProcessLabels {
	binary, pod, workload, ns := oss.GetProcessInfo(res)
	processLabels := metrics.NewProcessLabels(ns, workload, pod, binary, "")

	if !labelFilter["namespace"] {
		processLabels.Namespace = ""
	}
	if !labelFilter["workload"] {
		processLabels.Workload = ""
	}
	if !labelFilter["pod"] {
		processLabels.Pod = ""
	}
	if !labelFilter["binary"] {
		processLabels.Binary = ""
	}

	return processLabels
}

func createSocketLabels(labelFilter metrics.LabelFilter, res *tetragon.ProcessSockStats) *socketmetrics.SocketLabels {
	processLabels := createProcessLabels(labelFilter, res.Process)
	socketLabels := getSocketInfo(processLabels, res.Socket)

	// NOTE: Process labels are filtered already in createProcessLabels.
	if !labelFilter["dstnamespace"] {
		socketLabels.DstNs = ""
	}
	if !labelFilter["dstworkload"] {
		socketLabels.DstWorkload = ""
	}
	if !labelFilter["dstpod"] {
		socketLabels.DstPod = ""
	}
	if !labelFilter["dstdns"] {
		socketLabels.DstDNS = ""
	}
	if !labelFilter["dstip"] {
		socketLabels.DstIp = ""
	}

	return socketLabels
}

func createMulticastSocketLabels(res *tetragon.ProcessSockStats) *socketmetrics.MulticastSocketLabels {
	processLabels := createProcessLabels(udpconfig.CurrentLabels, res.Process)
	socketLabels := getSocketInfo(processLabels, res.Socket)
	var srcMcast string
	if res.Socket != nil {
		srcMcast = res.Socket.SourceIp
	}
	// If we have a connection ID, add it to the source IP address.
	// Note, if the socket is nil, the string will simply be "#<conn_id>",
	// with the "#" indicating that there is a missing IP address. We use
	// "#" as ":" could be mistaken for a port separator and "/" a netmask
	// separator.
	if res.ConnectionId != 0 {
		srcMcast += fmt.Sprintf("#%d", res.ConnectionId)
	}
	mcastLabels := socketmetrics.NewMulticastSocketLabels(
		socketLabels.Namespace, socketLabels.Workload, socketLabels.Pod, socketLabels.Binary,
		srcMcast,
		socketLabels.DstNs, socketLabels.DstWorkload, socketLabels.DstPod,
		socketLabels.DstIp,
	)

	// NOTE: Process labels are filtered already in createProcessLabels.
	if !udpconfig.CurrentLabels["dstnamespace"] {
		mcastLabels.DstNs = ""
	}
	if !udpconfig.CurrentLabels["dstworkload"] {
		mcastLabels.DstWorkload = ""
	}
	if !udpconfig.CurrentLabels["dstpod"] {
		mcastLabels.DstPod = ""
	}
	if !udpconfig.CurrentLabels["srcmcast"] {
		mcastLabels.SrcMcast = ""
	}
	if !udpconfig.CurrentLabels["dstmcast"] {
		mcastLabels.DstMcast = ""
	}

	return mcastLabels
}

func createHTTPLabels(res *tetragon.ProcessHttp) *httpmetrics.HTTPLabels {
	processLabels := createProcessLabels(httpconfig.MetricsLabelFilter, res.Process)
	socketLabels := getSocketInfo(processLabels, res.Socket)
	var host string
	if res.Http != nil {
		if res.Http.Request != nil {
			host = res.Http.Request.Host
		}
	}
	httpLabels := httpmetrics.NewHTTPLabels(
		socketLabels.Namespace, socketLabels.Workload, socketLabels.Pod, socketLabels.Binary,
		socketLabels.DstNs, socketLabels.DstWorkload, socketLabels.DstPod, socketLabels.DstDNS,
		host,
	)

	// NOTE: Process labels are filtered already in createProcessLabels.
	if !httpconfig.MetricsLabelFilter["dstnamespace"] {
		httpLabels.DstNamespace = ""
	}
	if !httpconfig.MetricsLabelFilter["dstworkload"] {
		httpLabels.DstWorkload = ""
	}
	if !httpconfig.MetricsLabelFilter["dstpod"] {
		httpLabels.DstPod = ""
	}
	if !httpconfig.MetricsLabelFilter["dstdns"] {
		httpLabels.DstDNS = ""
	}
	if !httpconfig.MetricsLabelFilter["host"] {
		httpLabels.Host = ""
	}

	return httpLabels
}
