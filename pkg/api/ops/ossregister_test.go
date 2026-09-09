// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package ops

import (
	"strings"
	"testing"

	ossops "github.com/cilium/tetragon/pkg/api/ops"
	"github.com/stretchr/testify/require"
)

func TestOpCodeString(t *testing.T) {
	tests := []struct {
		name    string
		resolve func(OpCode) string
		op      OpCode
		want    string
	}{
		{"enterprise-only opcode resolves", viaOSS, MSG_OP_IP_ERROR, "IPError"},
		{"enterprise-only opcode resolves (DNS)", viaOSS, MSG_OP_DNS, "DNS"},
		{"shared opcode keeps its OSS name", viaOSS, MSG_OP_EXECVE, "Execve"},
		{"shared opcode keeps its OSS name (exit)", viaOSS, MSG_OP_EXIT, "Exit"},
		{"unknown opcode does not re-enter the Stringer", viaEnterprise, 250, "Unknown(250)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, tt.resolve(tt.op))
		})
	}
}

func TestAllEnterpriseOpCodesResolveInOSSMap(t *testing.T) {
	for op, name := range OpCodeStrings {
		require.False(t, strings.HasPrefix(viaOSS(op), "Unknown("),
			"opcode %d (%s) is unknown to OSS", int(op), name)
	}
}

func viaOSS(op OpCode) string { return ossops.OpCode(op).String() }

func viaEnterprise(op OpCode) string { return op.String() }
