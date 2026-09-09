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
	ossops "github.com/cilium/tetragon/pkg/api/ops"
)

// OSS code reconstructs an ops.OpCode from the raw op byte of an event and
// resolves it through its own map.
func init() {
	for op, name := range OpCodeStrings {
		if _, ok := ossops.OpCodeStrings[ossops.OpCode(op)]; !ok {
			ossops.OpCodeStrings[ossops.OpCode(op)] = name
		}
	}
}
