// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

// This file contains some init code that serves to fix up the default filter list
// initialized in the OSS filters.go by adding enterprise-specific defaults.

package filters

import oss "github.com/cilium/tetragon/pkg/filters"

func init() {
	oss.Filters = append(oss.Filters, []oss.OnBuildFilter{
		&IPCIDRFilter{},
		&SourceCIDRFilter{},
		&DestCIDRFilter{},
		&URIRegexFilter{},
		&SNIRegexFilter{},
		&DestinationNamesRegexFilter{},
		&DestinationPodRegexFilter{},
		&DnsNamesRegexFilter{},
		&HostRegexFilter{},
		&ProtocolFilter{},
	}...)
}
