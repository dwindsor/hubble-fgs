// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build e2e_tests

package nodeselector_test

import (
	"testing"

	// Fix up OSS configuration defaults.
	_ "github.com/isovalent/hubble-fgs/tests/e2e/enterprise"
	nodeselectore2e "github.com/isovalent/hubble-fgs/tests/e2e/tests/common/nodeselector"

	install "github.com/cilium/tetragon/tests/e2e/install/tetragon"
	"github.com/cilium/tetragon/tests/e2e/runners"
)

// runner holds the test environment from runners.NewRunner().Setup().
var runner *runners.Runner

func TestMain(m *testing.M) {
	runner = runners.
		NewRunner().
		WithInstallTetragon(
			install.WithHelmOptions(map[string]string{
				"tetragon.exportAllowList": "",
			}),
		).
		Init()

	runner.Run(m)
}

func TestNodeSelector(t *testing.T) {
	nodeselectore2e.Test(t, runner)
}
