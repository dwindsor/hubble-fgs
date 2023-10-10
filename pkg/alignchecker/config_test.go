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
