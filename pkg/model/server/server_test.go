//go:build sudo_tests

package server_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper/docker"
	"github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/isovalent/hubble-fgs/pkg/bpftest"
	"github.com/isovalent/hubble-fgs/pkg/dnsparser"
	"github.com/isovalent/hubble-fgs/pkg/model"
	"github.com/isovalent/hubble-fgs/pkg/model/checker"
	"github.com/isovalent/hubble-fgs/pkg/model/server"
	"github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
	"github.com/isovalent/hubble-fgs/pkg/testutils"
	"github.com/isovalent/ipa/application_model/v1alpha"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

	t.Run("DNSPolicy", testDNSQuotaPolicy)
}

func testDNSQuotaPolicy(t *testing.T) {
	if !utils.SupportDNSParser() || !utils.SupportProcessTree() {
		t.Skip()
	}

	// Start an HTTP server serving 128 null bytes on localhost:8080
	testutils.StartSimpleHTTPServer(t, ":8080")

	// Specifying --ipv4 to ask curl not to fallback to IPv6 when IPv4
	// failed on dual stack host, otherwise we escape the quota limitation
	// which is not yet ready for IPv6.
	curlArg := []string{"--max-time", "0.1", "--ipv4", "localhost:8080"}

	// Check that curl to the domain works
	// Note: wanted to use the Go HTTP request directly but the issue is
	// that the socket is reused between this test and the one after
	// tetragon started
	curlCmd := exec.Command("curl", curlArg...)
	err := curlCmd.Run()
	require.NoError(t, err)

	// Now start tetragon with a quota policy
	var doneWG sync.WaitGroup
	defer doneWG.Wait()

	// Note that right now, we don't transmit the port information to the
	// BPF side so, putting port: [] would result in the same as port: [any]
	const policy = `
apiversion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "layer3"
spec:
  parser:
    tcp:
      qos:
        quotaReset: "5m"
        quotaLimits:
        - destination:
            dns: ["localhost"]
            port: [8080]
          quota: "1"
`

	tp, err := tracingpolicy.FromYAML(policy)
	require.NoError(t, err)
	err = observer.GetSensorManager().AddTracingPolicy(t.Context(), tp)
	require.NoError(t, err)
	t.Cleanup(func() {
		err = observer.GetSensorManager().DeleteTracingPolicy(context.Background(), tp.TpName(), "")
		require.NoError(t, err)
	})

	// We are forced to manually do a DNS request on localhost to populate
	// the DNS parser cache because curl no longer does it and automatically
	// hardcode localhost to 127.0.0.1 according to the RFC. See more at
	// https://daniel.haxx.se/blog/2021/05/31/curl-localhost-as-a-local-host/
	digCmd := exec.Command("dig", "localhost")
	err = digCmd.Run()
	require.NoError(t, err)

	// Verify that the BPF DNS parser was filled with the entry
	ipToIDMapsFile := filepath.Join(bpf.MapPrefixPath(), dnsparser.IPToIDMapsName)
	ipToIDMaps, err := ebpf.LoadPinnedMap(ipToIDMapsFile, nil)
	require.NoError(t, err)
	defer ipToIDMaps.Close()

	idToDomainMapFile := filepath.Join(bpf.MapPrefixPath(), dnsparser.IDToDomainMapName)
	idToDomainMap, err := ebpf.LoadPinnedMap(idToDomainMapFile, nil)
	require.NoError(t, err)
	defer idToDomainMap.Close()

	ipMap := dnsparser.NewIPToDomainMap(ipToIDMaps, idToDomainMap)

	values, err := ipMap.Values()
	require.NoError(t, err)
	domain, ok := values[netip.AddrFrom4([4]byte{127, 0, 0, 1})]
	require.True(t, ok, "BPF DNS parser maps are missing the 127.0.0.1 -> localhost entry")
	assert.Equal(t, "localhost", domain, "127.0.0.1 does not point to the localhost domain")

	// Check that the response is now blocked by the policy
	curlCmd = exec.Command("curl", curlArg...)
	err = curlCmd.Run()
	require.Error(t, err)
	exitErr, ok := err.(*exec.ExitError)
	require.True(t, ok)
	assert.Equal(t, 28, exitErr.ExitCode(), "wrong exit code: curl should exit with 28 (timeout)")
}
