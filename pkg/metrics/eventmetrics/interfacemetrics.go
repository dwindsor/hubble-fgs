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
	"github.com/cilium/tetragon/api/v1/tetragon"

	"github.com/isovalent/hubble-fgs/pkg/metrics/interfacemetrics"
)

func HandleInterfaceStatsEvent(res *tetragon.InterfaceStats) {
	name := res.InterfaceName
	var ns, workload, pod string

	if res.Pod != nil {
		ns = res.Pod.Namespace
		workload = res.Pod.Workload
		pod = res.Pod.Name
	}

	interfacemetrics.InterfaceBytesSent.WithLabelValues(name, ns, workload, pod).Set(float64(res.BytesSent))
	interfacemetrics.InterfaceBytesReceived.WithLabelValues(name, ns, workload, pod).Set(float64(res.BytesReceived))
	interfacemetrics.InterfaceSegmentsSent.WithLabelValues(name, ns, workload, pod).Set(float64(res.PacketsSent))
	interfacemetrics.InterfaceSegmentsReceived.WithLabelValues(name, ns, workload, pod).Set(float64(res.PacketsReceived))
	interfacemetrics.InterfaceTxErrors.WithLabelValues(name, ns, workload, pod).Set(float64(res.TxErrors))
	interfacemetrics.InterfaceRxErrors.WithLabelValues(name, ns, workload, pod).Set(float64(res.RxErrors))
	interfacemetrics.InterfaceTxDrops.WithLabelValues(name, ns, workload, pod).Set(float64(res.TxDrops))
	interfacemetrics.InterfaceRxDrops.WithLabelValues(name, ns, workload, pod).Set(float64(res.RxDrops))
}
