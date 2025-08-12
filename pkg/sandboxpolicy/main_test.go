// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build sudo_tests

package sandboxpolicy

import (
	"os"
	"testing"

	tus "github.com/cilium/tetragon/pkg/testutils/sensors"

	"github.com/isovalent/hubble-fgs/pkg/testutils"
)

func TestMain(m *testing.M) {
	tus.ConfigDefaults.TetragonLib = testutils.RepoRootPath("bpf/objs")
	ec := tus.TestSensorsRun(m, "SandboxPolicyTest")
	os.Exit(ec)
}
