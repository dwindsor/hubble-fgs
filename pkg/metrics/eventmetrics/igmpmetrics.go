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
	oss "github.com/cilium/tetragon/pkg/metrics/eventmetrics"

	"github.com/cilium/tetragon/api/v1/tetragon"

	"github.com/isovalent/hubble-fgs/pkg/metrics/igmpmetrics"
)

func postIgmpJoinStats(res *tetragon.ProcessIgmpJoin) {
	binary, pod, workload, ns := oss.GetProcessInfo(res.Process)

	igmpmetrics.IgmpJoinsVol.WithLabelValues(ns, workload, pod, binary, "", res.GroupIp).Inc()
}

func postIgmpLeaveStats(res *tetragon.ProcessIgmpLeave) {
	binary, pod, workload, ns := oss.GetProcessInfo(res.Process)

	igmpmetrics.IgmpLeavesVol.WithLabelValues(ns, workload, pod, binary, "", res.GroupIp).Inc()
}

func postIgmpMemberhsipReportStats(res *tetragon.IgmpMembershipReport) {
	igmpmetrics.IgmpGroupMembershipVol.WithLabelValues("", res.GroupIp, res.Type.String()).Inc()
}

func HandleIgmpJoinEvent(res *tetragon.ProcessIgmpJoin) {
	postIgmpJoinStats(res)
}

func HandleIgmpLeaveEvent(res *tetragon.ProcessIgmpLeave) {
	postIgmpLeaveStats(res)
}

func HandleIgmpMembershipReportEvent(res *tetragon.IgmpMembershipReport) {
	postIgmpMemberhsipReportStats(res)
}
