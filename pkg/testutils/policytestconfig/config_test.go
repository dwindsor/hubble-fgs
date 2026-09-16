// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build !windows

package policytestconfig

import (
	"path/filepath"
	"testing"

	policytestcmd "github.com/cilium/tetragon/cmd/tetra/policytest"
	"github.com/stretchr/testify/require"
)

func TestEnterpriseTestBinary(t *testing.T) {
	previousEnterpriseBinsDir := enterpriseBinsDir
	SetEnterpriseBinsDir("/host/build/src/hubble-fgs/contrib/tester-progs")
	t.Cleanup(func() { enterpriseBinsDir = previousEnterpriseBinsDir })

	require.Equal(t,
		"/host/build/src/hubble-fgs/contrib/tester-progs/read_write/read",
		EnterpriseTestBinary("read_write/read"),
	)
}

func TestDefaultEnterpriseTestBinary(t *testing.T) {
	previousEnterpriseBinsDir := enterpriseBinsDir
	SetEnterpriseBinsDir(defaultEnterpriseBinsDir())
	t.Cleanup(func() { enterpriseBinsDir = previousEnterpriseBinsDir })

	require.Equal(t,
		filepath.Join(enterpriseBinsDir, "read_write/read"),
		EnterpriseTestBinary("read_write/read"),
	)
}

func TestAddEnterprisePolicyTestFlags(t *testing.T) {
	previousEnterpriseBinsDir := enterpriseBinsDir
	enterpriseBinsDir = ""
	t.Cleanup(func() { enterpriseBinsDir = previousEnterpriseBinsDir })

	command := policytestcmd.New()
	AddEnterprisePolicyTestFlags(command)
	require.Equal(t, defaultEnterpriseBinsDir(), enterpriseBinsDir)

	runCommand, _, err := command.Find([]string{"run"})
	require.NoError(t, err)
	require.NoError(t, runCommand.ParseFlags([]string{"--ee-bindir", "/tmp/enterprise-bins"}))
	require.Equal(t, "/tmp/enterprise-bins", enterpriseBinsDir)
}
