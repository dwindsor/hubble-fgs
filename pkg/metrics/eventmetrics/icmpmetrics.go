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
	"strings"

	"github.com/cilium/tetragon/api/v1/tetragon"
	oss "github.com/cilium/tetragon/pkg/metrics/eventmetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/icmpmetrics"
)

func postIcmpStats(res *tetragon.ProcessIcmp) {
	binary, pod, workload, ns := oss.GetProcessInfo(res.Process)
	var dstpod, dstworkload, dstns string
	if res.DestinationPod != nil {
		dstns = res.DestinationPod.Namespace
		dstworkload = res.DestinationPod.Workload
		dstpod = res.DestinationPod.Name
	}
	dstDNS := strings.Join(res.DestinationNames, ",")

	icmpmetrics.IcmpStatsVol.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstDNS).Inc()
}

func HandleIcmpEvent(res *tetragon.ProcessIcmp) {
	postIcmpStats(res)
}
