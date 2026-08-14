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
	"context"
	"net"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/kernels"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper/docker"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors/config/confmap"
	osstestutils "github.com/cilium/tetragon/pkg/testutils"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/stretchr/testify/suite"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"

	"github.com/cilium/tetragon/pkg/jsonchecker"

	enterpriseoth "github.com/isovalent/hubble-fgs/pkg/observer/observertesthelper"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3"
	cli "github.com/isovalent/hubble-fgs/pkg/testutils/cliswitches"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"

	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
)

type TCPDocker struct {
	TCPCommon
}

func TestTCPDocker(t *testing.T) {
	suite.Run(t, new(TCPDocker))
}

func TestTCPDockerCLI(t *testing.T) {
	suite.Run(t, new(TCPDocker{TCPCommon: TCPCommon{useCLI: true}}))
}

func (suite *TCPDocker) SetupSuite() {
	suite.ctx, suite.cancel = context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	suite.startDockerTCPServices()
	if suite.useCLI {
		var err error
		suite.switches, err = cli.SetConfigFromSwitches([]cli.SwitchSettings{
			{KeyPtr: &enterpriseOption.Config.Layer3CLIEnable, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableNetworkEvents, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableTCP, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableTCPMetrics, Value: true},
		})
		suite.Require().NoError(err)
	}
	obs := enterpriseoth.GetNoConfigObserver(suite.T(), suite.ctx, false)
	suite.Require().NoError(layer3.StartLayer3Progs(suite.ctx, nil))

	if !suite.useCLI {
		tp, err := tracingpolicy.FromYAML(tcpBasicConfig)
		suite.Require().NoError(err)
		err = observer.GetSensorManager().AddTracingPolicy(suite.ctx, tp)
		suite.Require().NoError(err)
	}

	option.Config.UsePerfRingBuffer = true
	confmap.UpdateTgRuntimeConf(bpf.MapPrefixPath(), os.Getpid())
	observertesthelper.LoopEvents(suite.ctx, suite.T(), &suite.doneWG, &suite.readyWG, obs)
}

func (suite *TCPDocker) HandleStats(_ string, stats *suite.SuiteInformation) {
	if stats.Passed() {
		osstestutils.DoneWithExportFile(suite.T())
	}
}

func (suite *TCPDocker) TearDownSuite() {
	suite.cancel()
	suite.stopDockerTCPServices()
	cli.RevertSwitchesConfig(suite.switches)
}

func (suite *TCPDocker) startDockerTCPServices() {
	// Try removing container first as an existing one will cause the following line to fail.
	exec.Command("docker", "rm", "--force", "fgs-test-server").Run()
	/* Start server before creating obs */
	docker.Run(suite.T(), "--name", "fgs-test-server", "--entrypoint", "nc", alpineCurlImage, "-nvlp", "8087", "-s", "0.0.0.0")
	observertesthelper.WaitForProcess("nc -nvlp 8087 -s 0.0.0.0")
	// Try removing container first as an existing one will cause the following line to fail.
	exec.Command("docker", "rm", "--force", "fgs-test-server-v6").Run()
	/* Start server before creating obs */
	docker.Run(suite.T(), "--name", "fgs-test-server-v6", "--entrypoint", "nc", alpineCurlImage, "-nvlp", "8086", "-s", "[::]")
	observertesthelper.WaitForProcess("nc -nvlp 8086 -s [::]")
}

func (suite *TCPDocker) stopDockerTCPServices() {
	exec.Command("docker", "rm", "--force", "fgs-test-server").Run()
	exec.Command("docker", "rm", "--force", "fgs-test-server-v6").Run()
}

func (suite *TCPDocker) TestDockerExistingListenEvent4() {
	if runtime.GOARCH != "amd64" && !kernels.MinKernelVersion("5.8.0") {
		suite.T().Skip("Test requires amd64 or kernel >=5.8")
	}

	if err := exec.Command("docker", "version").Run(); err != nil {
		suite.T().Skipf("docker not available. skipping test: %s", err)
	}
	suite.readyWG.Wait()

	// Ideally we would also verify the dockerID, but our current dockerID
	// scanner from procFS does not match github actions docker env that
	// does not prepend a 'docker' string to the cgroup name. For now
	// drop the comparison and just ensure we get the events.
	//fgsServerID := serverDockerID[:31]

	// Current code reports binary behind symlink in proc case (binaries running
	// before fgs starts), but in runtime event we report the name of the symlink.
	// In this test the difference is busybox vs nc.
	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix("busybox")).
		WithArguments(sm.Full("-nvlp 8087 -s 0.0.0.0")).
		WithCwd(sm.Full("/")).
		WithUid(0)

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("ncExec").
			WithProcess(ncChecker),
		ec.NewProcessListenChecker("ncListen").
			WithProcess(ncChecker).
			WithIp(sm.Full("0.0.0.0")).
			WithPort(8087).
			WithProtocol(tetragon.SocketProtocol_TCP),
	)

	err := jsonchecker.JsonTestCheck(suite.T(), checker)
	suite.Assert().NoError(err)
}

func (suite *TCPDocker) TestDockerListenConnect4() {
	if runtime.GOARCH != "amd64" && !kernels.MinKernelVersion("5.8.0") {
		suite.T().Skip("Test requires amd64 or kernel >=5.8")
	}

	if err := exec.Command("docker", "version").Run(); err != nil {
		suite.T().Skipf("docker not available. skipping test: %s", err)
	}

	suite.readyWG.Wait()
	// Try removing container first as an existing one will cause the following line to fail.
	exec.Command("docker", "rm", "--force", "fgs-test-server").Run()
	serverDockerID := docker.Run(suite.T(), "--name", "fgs-test-server", "--entrypoint", "nc", alpineCurlImage, "-nvlp", "8088", "-s", "0.0.0.0")
	time.Sleep(1 * time.Second)
	clientDockerID := docker.Run(suite.T(), "--link", "fgs-test-server", "--entrypoint", "nc", alpineCurlImage, "-p", "9876", "fgs-test-server", "8088")

	// FGS sends 31 bytes + \0 to user-space. Since it might have an arbitrary prefix,
	// match only on the first 24 bytes.
	fgsServerID := sm.Prefix(serverDockerID[:24])
	fgsClientID := sm.Prefix(clientDockerID[:24])

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncSrvChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix("/nc")).
		WithArguments(sm.Full("-nvlp 8088 -s 0.0.0.0")).
		WithCwd(sm.Full("/")).
		WithUid(0).
		WithDocker(fgsServerID)

	ncCliChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix("/nc")).
		WithArguments(sm.Full("-p 9876 fgs-test-server 8088")).
		WithCwd(sm.Full("/")).
		WithUid(0).
		WithDocker(fgsClientID)

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("serverExec").
			WithProcess(ncSrvChecker),
		ec.NewProcessListenChecker("serverListen").
			WithProcess(ncSrvChecker).
			WithIp(sm.Full("0.0.0.0")).
			WithPort(8088).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessExecChecker("clientExec").
			WithProcess(ncCliChecker),
		ec.NewProcessConnectChecker("clientConnect").
			WithProcess(ncCliChecker).
			WithDestinationPort(8088).
			WithSourcePort(9876).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessCloseChecker("serverClose").
			WithProcess(ncSrvChecker).
			WithSourceIp(sm.Full("0.0.0.0")).
			WithSourcePort(8088).
			WithProtocol(tetragon.SocketProtocol_TCP).
			WithSocketType(sm.Full("listen")),
		ec.NewProcessCloseChecker("clientClose").
			WithProcess(ncCliChecker).
			WithDestinationPort(8088).
			WithSourcePort(9876).
			WithProtocol(tetragon.SocketProtocol_TCP).
			WithSocketType(sm.Full("connect")),
	)

	// Wait for the sockets to close
	err := waitAndCheckForSocketsToClose(suite.T(), checker, net.ParseIP("127.0.0.1"), 8088, syscall.IPPROTO_TCP, syscall.AF_INET)
	suite.Assert().NoError(err)
}

func (suite *TCPDocker) TestDockerExistingListenEvent6() {
	if runtime.GOARCH != "amd64" && !kernels.MinKernelVersion("5.8.0") {
		suite.T().Skip("Test requires amd64 or kernel >=5.8")
	}

	if err := exec.Command("docker", "version").Run(); err != nil {
		suite.T().Skipf("docker not available. skipping test: %s", err)
	}
	suite.readyWG.Wait()

	// Ideally we would also verify the dockerID, but our current dockerID
	// scanner from procFS does not match github actions docker env that
	// does not prepend a 'docker' string to the cgroup name. For now
	// drop the comparison and just ensure we get the events.
	//fgsServerID := serverDockerID[:31]

	// Current code reports binary behind symlink in proc case (binaries running
	// before fgs starts), but in runtime event we report the name of the symlink.
	// In this test the difference is busybox vs nc.
	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix("busybox")).
		WithArguments(sm.Full("-nvlp 8086 -s [::]")).
		WithCwd(sm.Full("/")).
		WithUid(0)

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("ncExec").
			WithProcess(ncChecker),
		ec.NewProcessListenChecker("ncListen").
			WithProcess(ncChecker).
			WithIp(sm.Full("::")).
			WithPort(8086).
			WithProtocol(tetragon.SocketProtocol_TCP),
	)

	err := jsonchecker.JsonTestCheck(suite.T(), checker)
	suite.Assert().NoError(err)
}

func (suite *TCPDocker) TestDockerListenConnect6() {
	if runtime.GOARCH != "amd64" && !kernels.MinKernelVersion("5.8.0") {
		suite.T().Skip("Test requires amd64 or kernel >=5.8")
	}

	if err := exec.Command("docker", "version").Run(); err != nil {
		suite.T().Skipf("docker not available. skipping test: %s", err)
	}

	suite.readyWG.Wait()
	// Try removing container first as an existing one will cause the following line to fail.
	exec.Command("docker", "rm", "--force", "fgs-test-server-v6").Run()
	serverDockerID := docker.Run(suite.T(), "--name", "fgs-test-server-v6", "--entrypoint", "nc", alpineCurlImage, "-nvlp", "8087", "-s", "[::]")
	time.Sleep(1 * time.Second)
	clientDockerID := docker.Run(suite.T(), "--link", "fgs-test-server-v6", "--entrypoint", "nc", alpineCurlImage, "-p", "9876", "fgs-test-server-v6", "8087")

	// FGS sends 31 bytes + \0 to user-space. Since it might have an arbitrary prefix,
	// match only on the first 24 bytes.
	fgsServerID := sm.Prefix(serverDockerID[:24])
	fgsClientID := sm.Prefix(clientDockerID[:24])

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncSrvChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix("/nc")).
		WithArguments(sm.Full("-nvlp 8087 -s [::]")).
		WithCwd(sm.Full("/")).
		WithUid(0).
		WithDocker(fgsServerID)

	ncCliChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix("/nc")).
		WithArguments(sm.Full("-p 9876 fgs-test-server-v6 8087")).
		WithCwd(sm.Full("/")).
		WithUid(0).
		WithDocker(fgsClientID)

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("severExec").
			WithProcess(ncSrvChecker),
		ec.NewProcessListenChecker("serverListen").
			WithProcess(ncSrvChecker).
			WithIp(sm.Full("::")).
			WithPort(8087).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessExecChecker("clientExec").
			WithProcess(ncCliChecker),
		ec.NewProcessConnectChecker("clientConnect").
			WithProcess(ncCliChecker).
			WithDestinationPort(8087).
			WithSourcePort(9876).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessCloseChecker("serverClose").
			WithProcess(ncSrvChecker).
			WithSourceIp(sm.Full("::")).
			WithSourcePort(8087).
			WithProtocol(tetragon.SocketProtocol_TCP).
			WithSocketType(sm.Full("listen")),
		ec.NewProcessCloseChecker("clientClose").
			WithProcess(ncCliChecker).
			WithDestinationPort(8087).
			WithSourcePort(9876).
			WithProtocol(tetragon.SocketProtocol_TCP).
			WithSocketType(sm.Full("connect")),
	)

	// Wait for the sockets to close
	err := waitAndCheckForSocketsToClose(suite.T(), checker, net.ParseIP("::1"), 8087, syscall.IPPROTO_TCP, syscall.AF_INET)
	suite.Assert().NoError(err)
}
