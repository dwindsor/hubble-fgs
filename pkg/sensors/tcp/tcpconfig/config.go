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
	"fmt"
	"strings"

	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/isovalent/hubble-fgs/pkg/sensors/networklatency"
)

var (
	MetricsEnabled  = false
	LatencyConfig   networklatency.ProtocolConfig
	RttHistogramMax uint32
	RttHistogramMin uint32
	CurrentLabels   = DefaultLabelFilter()
)

func DefaultLabelFilter() metrics.LabelFilter {
	return metrics.LabelFilter{
		"namespace":    true,
		"workload":     true,
		"pod":          true,
		"binary":       true,
		"dstnamespace": true,
		"dstworkload":  true,
		"dstpod":       true,
		"dstdns":       true,
		"dstip":        false,
	}
}

func zeroLabels(l map[string]bool) {
	for k := range CurrentLabels {
		l[k] = false
	}
}

func ConfigureLabels(masks []string) error {
	var unknownMasks []string

	if len(masks) == 0 {
		return nil
	}

	zeroLabels(CurrentLabels)

	for _, v := range masks {
		_, ok := CurrentLabels[v]
		if !ok {
			unknownMasks = append(unknownMasks, v)
			continue
		}
		CurrentLabels[v] = true
	}
	if len(unknownMasks) > 0 {
		return fmt.Errorf("Unknown masks: %s", strings.Join(unknownMasks, ","))
	}
	return nil
}
