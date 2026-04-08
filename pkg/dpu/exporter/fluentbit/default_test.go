// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package fluentbit

import (
	"strings"
	"testing"
)

func TestDefaultDpSyslogInputUsesDirectionalLogicalNetworkFields(t *testing.T) {
	input := DefaultDpSyslogInput()
	if len(input.Processors.Logs) != 1 {
		t.Fatalf("expected one log processor, got %d", len(input.Processors.Logs))
	}

	code := input.Processors.Logs[0].Properties["code"]
	for _, field := range []string{
		`src_vlan=`,
		`dst_vlan=`,
		`src_vrf=`,
		`dst_vrf=`,
		`record["src_vlan"]`,
		`record["dst_vlan"]`,
		`record["src_vrf"]`,
		`record["dst_vrf"]`,
	} {
		if !strings.Contains(code, field) {
			t.Fatalf("expected dp syslog formatter to contain %q", field)
		}
	}
}
