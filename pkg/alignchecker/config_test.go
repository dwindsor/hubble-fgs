// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package alignchecker_test

import (
	"flag"
	"os"
	"path/filepath"

	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"
)

var tetragonLib string

func init() {
	flag.StringVar(&tetragonLib, "bpf-lib", filepath.Join(runner.TetragonBpfPath(), "objs"), "tetragon lib directory (location of btf file and bpf objs). Will be overridden by an TETRAGON_LIB env variable.")

	tetragonLibEnv := os.Getenv("TETRAGON_LIB")
	if tetragonLibEnv != "" {
		tetragonLib = tetragonLibEnv
	}
}
