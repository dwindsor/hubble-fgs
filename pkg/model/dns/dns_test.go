package dns

import (
	"os"
	"testing"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"
)

func TestMain(m *testing.M) {
	bpf.CheckOrMountCgroup2()
	option.Config.EnablePolicyFilter = true
	option.Config.EnablePolicyFilter = true
	option.Config.EnablePolicyFilterCgroupMap = true
	prog = &DummyBpfProgrammer{}
	ec := runner.TestSensorsRun(m, "ModelDns")
	os.Exit(ec)
}
