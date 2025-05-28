//go:build sudo_tests

package alignchecker_test

import (
	"path/filepath"
	"testing"

	"github.com/isovalent/hubble-fgs/pkg/alignchecker"
	"github.com/stretchr/testify/assert"

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
