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
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

func defaultEnterpriseBinsDir() string {
	workingDir, _ := os.Getwd()
	return filepath.Join(workingDir, "contrib/tester-progs")
}

var enterpriseBinsDir string

func SetEnterpriseBinsDir(binsDir string) {
	enterpriseBinsDir = binsDir
}

func AddEnterprisePolicyTestFlags(policyTestCommand *cobra.Command) {
	enterpriseBinsDir = defaultEnterpriseBinsDir()
	for _, command := range policyTestCommand.Commands() {
		if command.Name() != "run" && command.Name() != "dump-policy" {
			continue
		}

		command.Flags().StringVar(&enterpriseBinsDir, "ee-bindir", enterpriseBinsDir, "path for enterprise test binaries directory")
	}
}

func EnterpriseTestBinary(relativePath string) string {
	return filepath.Join(enterpriseBinsDir, relativePath)
}
