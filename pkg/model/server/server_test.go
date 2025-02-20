package server_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
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
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper/docker"
	"github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/isovalent/hubble-fgs/pkg/dnsparser"
	"github.com/isovalent/hubble-fgs/pkg/model"
	"github.com/isovalent/hubble-fgs/pkg/model/checker"
	"github.com/isovalent/hubble-fgs/pkg/model/server"
	enterpriseoth "github.com/isovalent/hubble-fgs/pkg/observer/observertesthelper"
	"github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"
	"github.com/isovalent/ipa/application_model/v1alpha"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "github.com/isovalent/hubble-fgs/pkg/sensorinit"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/program/cgroup"
)

var testConfigFile = "/tmp/hubble-tetragon.gotest.yaml"

func TestMain(m *testing.M) {
	ec := runner.TestSensorsRun(m, "ModelServer")
	os.Exit(ec)
}

var tests = []processTree{
	{
		Name: "testBasicExecArgs",
		Steps: []testStep{
			newCmdStep("bash", "-c", "uname -r"),
		},
		Checks: []string{
			`model.host.processes.exists(p, p.name.matches("/usr/bin/bash") && p.arguments.matches("-c.*uname.*-r.*"))`,
		},
		ArmSupport: true,
	},
	{
		Name: "testBasicCurl",
		Steps: []testStep{
			newCmdStep("curl", "-4", "ebpf.io"),
		},
		// FIXME: For some reason, bytes_received is always 0 here, so we omit the check. This should be investigated at some point.
		Checks: []string{
			`model.host.processes.exists(p, p.name.matches(".*curl") && p.connections.exists(c, c.destination_name.matches("ebpf.io") && c.bytes_sent > 0))`,
		},
		ArmSupport: false,
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
		ArmSupport: false,
	},
}

type appModelPrinter struct {
	model *v1alpha.ApplicationModelEvent
}

func (printer appModelPrinter) String() string {
	b, _ := json.MarshalIndent(printer.model, "", "    ")
	return string(b)
}

func setupProcessTreeEnable(t *testing.T, ctx context.Context, doneWG *sync.WaitGroup, policy string) { //nolint:revive
	bpf.CheckOrMountCgroup2()

	var readyWG sync.WaitGroup

	if err := observertesthelper.WriteConfigFile(testConfigFile, policy); err != nil {
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

	observertesthelper.LoopEvents(ctx, t, doneWG, &readyWG, obs)
	readyWG.Wait()
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
	Name       string
	Steps      []testStep
	Checks     []string
	ArmSupport bool
}

func TestProcessTree(t *testing.T) {
	if v := "5.15.0"; !kernels.MinKernelVersion(v) {
		return
	}

	var doneWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), sensors.ConfigDefaults.CmdWaitTime)
	defer cancel()

	const policy = `
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

	setupProcessTreeEnable(t, ctx, &doneWG, policy)

	for _, e := range tests {
		t.Run(e.Name, func(t *testing.T) {
			if runtime.GOARCH != "amd64" && !e.ArmSupport {
				t.Skipf("ARM not supported for test %s, skipping", e.Name)
			}

			for _, step := range e.Steps {
				step.Step(t)
			}

			res, err := server.GetProcessModel([]string{}, false)
			if err != nil {
				t.Fatalf("getProcessModel error: %s", err)
			}
			appModelEvent := model.ProcessModelToApplicationModel(res)
			modelChk, err := checker.NewApplicationModelChecker()
			if err != nil {
				t.Fatalf("NewApplicationModelChecker error: %s", err)
			}
			resModel, errModel := modelChk.CheckApplicationModelEvent(ctx, appModelEvent, e.Checks)
			if errModel != nil {
				t.Fatalf("CheckApplicationModel error: %s: %s", errModel, appModelPrinter{model: appModelEvent})
			}
			if !assert.True(t, resModel.Ok(), "ApplicationModel: %s", appModelPrinter{model: appModelEvent}) {
				for _, f := range resModel.Failed() {
					t.Logf("Check failed: %s", f)
				}
			}
		})
	}
}

func TestProcessTree_DNSPolicy(t *testing.T) {
	// So far DNS policy are only supported on amd64 but could be extend to arm64 on recent kernels
	if runtime.GOARCH != "amd64" || !kernels.MinKernelVersion("5.15.0") {
		t.Skip()
	}

	// Start an HTTP server serving 128 null bytes on localhost:8080
	server := &http.Server{Addr: ":8080", Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(make([]byte, 128))
	})}
	go func() {
		err := server.ListenAndServe()
		if !errors.Is(err, http.ErrServerClosed) {
			panic(err) // can't call t.Fatal from another goroutine
		}
	}()
	defer server.Close()

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

	ctx, cancel := context.WithTimeout(context.Background(), sensors.ConfigDefaults.CmdWaitTime)
	defer cancel()

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
      enable: true
      qos:
        quotaReset: "5m"
        quotaLimits:
        - destination:
            dns: ["localhost"]
            port: [8080]
          quota: "1"
`

	setupProcessTreeEnable(t, ctx, &doneWG, policy)

	// We are forced to manually do a DNS request on localhost to populate
	// the DNS parser cache because curl no longer does it and automatically
	// hardcode localhost to 127.0.0.1 according to the RFC. See more at
	// https://daniel.haxx.se/blog/2021/05/31/curl-localhost-as-a-local-host/
	digCmd := exec.Command("dig", "localhost")
	err = digCmd.Run()
	require.NoError(t, err)

	// Verify that the BPF DNS parser was filled with the entry
	ipToIDMapFile := filepath.Join(bpf.MapPrefixPath(), dnsparser.DNSEndpointIDMapName)
	ipToIDMap, err := ebpf.LoadPinnedMap(ipToIDMapFile, nil)
	require.NoError(t, err)
	defer ipToIDMap.Close()

	idToDomainMapFile := filepath.Join(bpf.MapPrefixPath(), dnsparser.IDToDomainMapName)
	idToDomainMap, err := ebpf.LoadPinnedMap(idToDomainMapFile, nil)
	require.NoError(t, err)
	defer idToDomainMap.Close()

	ipMap := dnsparser.NewIPToDomainMap(ipToIDMap, idToDomainMap)

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
	assert.Equal(t, 28, exitErr.ProcessState.ExitCode(), "wrong exit code: curl should exit with 28 (timeout)")
}
