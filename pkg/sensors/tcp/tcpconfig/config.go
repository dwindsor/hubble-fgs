//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package tcpconfig

import (
	"github.com/isovalent/hubble-fgs/pkg/sensors/networklatency"
)

var (
	MetricsEnabled  = false
	LatencyConfig   networklatency.ProtocolConfig
	RttHistogramMax uint32
	RttHistogramMin uint32
)

type enableSocketLabels struct {
	Ns          bool
	Workload    bool
	Pod         bool
	Binary      bool
	Dstns       bool
	DstWorkload bool
	DstPod      bool
	DstLabels   bool
	DstIP       bool
	SourceIP    bool
}

var defaultLabels = enableSocketLabels{
	Ns:          true,
	Workload:    true,
	Pod:         true,
	Binary:      true,
	Dstns:       true,
	DstWorkload: true,
	DstPod:      true,
	DstLabels:   true,
	DstIP:       true,
	SourceIP:    true,
}

var CurrentLabels = defaultLabels
