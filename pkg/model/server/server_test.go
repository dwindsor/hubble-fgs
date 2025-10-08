//go:build sudo_tests

package server_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/tetragon/pkg/observer/observertesthelper/docker"
	"github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/isovalent/ipa/application_model/v1alpha"
	"github.com/stretchr/testify/assert"

	"github.com/isovalent/hubble-fgs/pkg/bpftest"
	"github.com/isovalent/hubble-fgs/pkg/model"
	"github.com/isovalent/hubble-fgs/pkg/model/checker"
	"github.com/isovalent/hubble-fgs/pkg/model/server"
	"github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
	"github.com/isovalent/hubble-fgs/pkg/testutils"

	_ "github.com/isovalent/hubble-fgs/pkg/sensorinit"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/program/cgroup"
)

var tests = []processTree{
	{
		Name: "testBasicExecArgs",
		Steps: []testStep{
			newCmdStep("bash", "-c", "uname -r"),
		},
		Checks: []string{
			`model.host.processes.exists(p, p.name.matches("/usr/bin/bash") && p.arguments.matches("-c.*uname.*-r.*"))`,
		},
	},
	{
		Name: "testBasicCurl",
		Steps: []testStep{
			newCmdStep("curl", "-4", "ebpf.io"),
		},
		// FIXME: For some reason, bytes_received is always 0 here, so we omit the check. This should be investigated at some point.
		Checks: []string{
			`model.host.processes.exists(p, p.name.matches(".*curl") && p.connections.exists(c, c.destination.dns.destination_names.exists(n, n.matches("ebpf.io")) && c.stats.tx_bytes > 0))`,
		},
	},
	{
		Name: "testInInitTree",
		Steps: []testStep{
			newDockerCreateStep("test-in-init-tree", "bash:5.2.37", "bash", "-c", "sleep infinity"),
			newDockerStartStep("test-in-init-tree"),
			newSleepStep(1 * time.Second),
			newDockerExecStep("test-in-init-tree", "bash", "-c", "echo testificate"),
		},
		Checks: []string{
			`model.host.processes.exists(p, p.name.matches("bash") && p.arguments.matches("-c \"sleep infinity\"") && p.in_init_tree)`,
			`model.host.processes.exists(p, p.name.matches("bash") && p.arguments.matches("-c \"echo testificate\"") && !p.in_init_tree)`,
		},
	},
	{
		Name: "testSyscallsRead",
		Steps: []testStep{
			newEnsureFileStep(testutils.RepoRootPath("contrib/tester-progs/read_write/read")),
			newCmdStep(testutils.RepoRootPath("contrib/tester-progs/read_write/read"), testutils.RepoRootPath("testdata/dummy_files/lorem.txt")),
		},
		Checks: []string{
			fmt.Sprintf(`model.host.processes.exists(p,
			    p.name.matches("tester-progs/read_write/read") &&
			    p.arguments.matches("testdata/dummy_files/lorem.txt") &&
			    sets.contains(p.syscall_info.syscalls, [
			        SYS_BRK,
			        SYS_OPENAT,
			        SYS_CLOSE,
			        SYS_MMAP,
			        SYS_SET_TID_ADDRESS,
			        SYS_SET_ROBUST_LIST,
			        SYS_RSEQ,
			        SYS_MPROTECT,
			        SYS_MUNMAP,
			        SYS_READ,
			        SYS_PRLIMIT64,
			        %s
			        %s
			        %s
			    ]))`,
				func() string {
					access := "SYS_ACCESS,"
					if runtime.GOARCH == "arm64" {
						access = "SYS_FACCESSAT,"
					}
					return access
				}(),
				func() string {
					pread := "SYS_PREAD64,"
					if runtime.GOARCH == "arm64" {
						pread = ""
					}
					return pread
				}(),
				func() string {
					prctl := "SYS_ARCH_PRCTL,"
					if runtime.GOARCH == "arm64" {
						prctl = ""
					}
					return prctl
				}()),
		},
	},
}

type appModelPrinter struct {
	model *v1alpha.ApplicationModelEvent
}

func (printer appModelPrinter) String() string {
	b, _ := json.Marshal(printer.model)
	return string(b)
}

type testStep interface {
	Step(testing.TB)
}

type cmdStep struct {
	cmd  string
	args []string
}

func (step *cmdStep) Step(tb testing.TB) {
	cmd := exec.Command(step.cmd, step.args...)
	err := cmd.Run()
	if err != nil {
		tb.Fatalf("failed to run command `%s %s`: %s", step.cmd, strings.Join(step.args, " "), err)
	}
}

func newCmdStep(cmd string, args ...string) *cmdStep {
	return &cmdStep{
		cmd,
		args,
	}
}

type ensureFileStep struct {
	path string
}

func (step *ensureFileStep) Step(tb testing.TB) {
	info, err := os.Stat(step.path)
	if errors.Is(err, os.ErrNotExist) {
		tb.Skipf("file %q does not exist", step.path)
	}
	if info.IsDir() {
		tb.Skipf("expected %q to be a file, found a directory", step.path)
	}
}

func newEnsureFileStep(path string) *ensureFileStep {
	return &ensureFileStep{
		path,
	}
}

type dockerCreateStep struct {
	containerName string
	imageTag      string
	args          []string
}

func (step *dockerCreateStep) Step(tb testing.TB) {
	dockerArgs := []string{"--name", step.containerName, step.imageTag}
	dockerArgs = append(dockerArgs, step.args...)
	docker.Create(tb, dockerArgs...)
}

func newDockerCreateStep(containerName string, imageTag string, args ...string) *dockerCreateStep {
	return &dockerCreateStep{
		containerName,
		imageTag,
		args,
	}
}

type dockerStartStep struct {
	containerName string
}

func (step *dockerStartStep) Step(tb testing.TB) {
	docker.Start(tb, step.containerName)
}

func newDockerStartStep(containerName string) *dockerStartStep {
	return &dockerStartStep{
		containerName,
	}
}

type dockerExecStep struct {
	containerName string
	args          []string
}

func (step *dockerExecStep) Step(tb testing.TB) {
	docker.Exec(tb, step.containerName, step.args...)
}

func newDockerExecStep(containerName string, args ...string) *dockerExecStep {
	return &dockerExecStep{
		containerName,
		args,
	}
}

type sleepStep struct {
	duration time.Duration
}

func (step *sleepStep) Step(_ testing.TB) {
	time.Sleep(step.duration)
}

func newSleepStep(duration time.Duration) *sleepStep {
	return &sleepStep{
		duration,
	}
}

type processTree struct {
	Name   string
	Steps  []testStep
	Checks []string
}

func TestProcessTree(t *testing.T) {
	if !utils.SupportProcessTree() {
		t.Skip()
	}

	var doneWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), sensors.ConfigDefaults.CmdWaitTime)
	defer cancel()

	option.Config.EnableSyscallTracking = true
	bpftest.StartMinimalTetragonModel(ctx, t)

	for _, e := range tests {
		t.Run(e.Name, func(t *testing.T) {
			for _, step := range e.Steps {
				step.Step(t)
			}

			// Add a small delay here to account for any races when fetching the application model.
			time.Sleep(1 * time.Second)

			res, err := server.GetProcessModel([]string{}, false)
			if err != nil {
				t.Fatalf("getProcessModel error: %s", err)
			}
			emptyFilter := make(map[string]bool, 0)
			appModelEvent := model.ProcessModelToApplicationModel(res, emptyFilter)
			modelChk, err := checker.NewApplicationModelChecker()
			if err != nil {
				t.Fatalf("NewApplicationModelChecker error: %s", err)
			}
			resModel, errModel := modelChk.CheckApplicationModelEvent(ctx, appModelEvent, e.Checks)
			if errModel != nil {
				t.Fatalf("CheckApplicationModel error: %s: %s", errModel, appModelPrinter{model: appModelEvent})
			}
			if !assert.True(t, resModel.Ok()) {
				t.Logf("ApplicationModel: %s", appModelPrinter{model: appModelEvent})
				for _, f := range resModel.Failed() {
					t.Logf("Check failed: %s", f)
				}
			}
		})
	}
}
