package server_test

import (
	"context"
	"os"
	"os/exec"
	"sync"
	"testing"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/isovalent/hubble-fgs/pkg/model"
	"github.com/isovalent/hubble-fgs/pkg/model/checker"
	"github.com/isovalent/hubble-fgs/pkg/model/server"
	enterpriseoth "github.com/isovalent/hubble-fgs/pkg/observer/observertesthelper"
	"github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"
	"github.com/stretchr/testify/assert"

	_ "github.com/isovalent/hubble-fgs/pkg/sensorinit"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/program/cgroup"
)

var testConfigFile = "/tmp/hubble-tetragon.gotest.yaml"

const config = `
apiversion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "layer3"
spec:
  parser:
    tcp:
      enable: true
    udp:
      enable: true
    dns:
      enable: false
`

func TestMain(m *testing.M) {
	ec := runner.TestSensorsRun(m, "ModelServer")
	os.Exit(ec)
}

func setupProcessTreeEnable(ctx context.Context, t *testing.T) {
	bpf.CheckOrMountCgroup2()

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	if err := observertesthelper.WriteConfigFile(testConfigFile, config); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}

	option.Config.EnableProcessTree = true
	option.Config.EnableBPFDNSParser = true

	base := base.GetInitialSensor()
	obs, err := enterpriseoth.GetDefaultObserverWithBase(t, ctx, base, testConfigFile, sensors.ConfigDefaults.TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}

	_, err = server.DefaultNewServer()
	if err != nil {
		t.Fatalf("Default NewServer  error: %s", err)
	}

	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()
}

type processTree struct {
	Name  string
	Cmd   string
	Args  []string
	Check string
}

var tests = []processTree{
	processTree{
		Name:  "testBasicExecArgs",
		Cmd:   "bash",
		Args:  []string{"-c", "uname -r"},
		Check: `model.host.processes.exists(p, p.name.matches("/usr/bin/bash") && p.arguments.matches("-c.*uname.*-r.*"))`,
	},
	processTree{
		Name:  "testBasicCurl",
		Cmd:   "curl",
		Args:  []string{"ebpf.io"},
		Check: `model.host.processes.exists(p, p.name.matches(".*curl") && p.connections.exists(c, c.destination_name.matches("ebpf.io")))`,
	},
}

func execTest(t *testing.T, e processTree) {
	cmd := exec.Command(e.Cmd, e.Args...)
	err := cmd.Run()
	if err != nil {
		t.Fatalf("exec input pattern failed: %s: %s\n", e.Cmd, err)
	}
}

func TestProcessTree(t *testing.T) {
	if v := "5.15.0"; !kernels.MinKernelVersion(v) {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), sensors.ConfigDefaults.CmdWaitTime)
	defer cancel()

	setupProcessTreeEnable(ctx, t)

	for _, e := range tests {
		t.Run(e.Name, func(t *testing.T) {
			execTest(t, e)

			res, err := server.GetProcessModel([]string{}, false)
			if err != nil {
				t.Fatalf("getProcessModel error: %s", err)
			}
			appModelEvent := model.ProcessModelToApplicationModel(res)
			modelChk, err := checker.NewApplicationModelChecker([]string{e.Check})
			if err != nil {
				t.Fatalf("NewApplicationModelChecker error: %s: %s", err, e.Check)
			}
			resModel, errModel := modelChk.CheckApplicationModelEvent(ctx, appModelEvent)
			if errModel != nil {
				t.Fatalf("CheckApplicationModel error: %s: %s", errModel, appModelEvent)
			}
			assert.True(t, resModel.Ok(), "ApplicationModel: %s", appModelEvent)
		})
	}
}
