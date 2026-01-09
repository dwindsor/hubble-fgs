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

package layer3_test

import (
	"path/filepath"
	"testing"

	check "github.com/cilium/tetragon/pkg/alignchecker"

	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"
)

func TestStructAlignments(t *testing.T) {
	path := filepath.Join(runner.Conf().TetragonLib, "bpf_alignchecker.o")
	// Validate alignments of C and Go equivalent structs
	toCheck := map[string][]any{
		"fd_lookup_config": {networkapi.FdLookupValue{}},
	}
	err := check.CheckStructAlignments(path, toCheck, true)
	if err != nil {
		t.Errorf("TestStructAlignments failed: %s\n", err)
	}
}
