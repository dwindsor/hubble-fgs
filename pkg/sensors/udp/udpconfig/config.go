//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package udpconfig

import (
	"github.com/isovalent/hubble-fgs/pkg/sensors/networklatency"
)

var (
	MetricsEnabled = false
	LatencyConfig  networklatency.ProtocolConfig
)

var defaultLabels = map[string]bool{
	"ns":          true,
	"workload":    true,
	"pod":         true,
	"binary":      true,
	"dstns":       true,
	"dstworkload": true,
	"dstpod":      true,
	"dstdns":      true,
	"srcmcast":    true,
	"dstmcast":    true,
	"dstip":       false,
}

var CurrentLabels = defaultLabels
