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

package alignchecker_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/isovalent/hubble-fgs/pkg/alignchecker"

	tetragonAlignchecker "github.com/cilium/tetragon/pkg/alignchecker"
)

func Test_EnterpriseAlignments(t *testing.T) {
	bpfObjPath := filepath.Join(tetragonLib, "bpf_alignchecker.o")
	err := alignchecker.CheckStructAlignments(bpfObjPath)
	assert.NoError(t, err, "enterprise types must align")
}

func Test_OSSAlignments(t *testing.T) {
	bpfObjPath := filepath.Join(tetragonLib, "bpf_alignchecker_oss.o")
	err := tetragonAlignchecker.CheckStructAlignmentsDefault(bpfObjPath)
	assert.NoError(t, err, "oss types must align")
}
