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
	"bufio"
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
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
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
	"github.com/isovalent/hubble-fgs/pkg/testutils"
	cli "github.com/isovalent/hubble-fgs/pkg/testutils/cliswitches"
	enterprisepolicytest "github.com/isovalent/hubble-fgs/pkg/testutils/policytest"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"
	_ "github.com/isovalent/hubble-fgs/tests/policytests"

	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
)

const tcpConfigLegacy = `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tcp"
spec:
  parser:
    tcp:
      enable: true
      statsInterval: 20
      burst:
        enable: true
        windowSize: 1000
        triggerPercent: 50
    burstExitGen:
      enable: true
      interval: 1000
    dns:
      enable: true
`

const tcpConfig = `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tcp"
spec:
  parser:
    tcp:
      enable: true
      statsInterval: 20
      watermarks:
        enable: true
        windowSize: 1000
        burstTriggerPercent: 50
        dipTriggerPercent: 10
    networkWatermarksExitGen:
      enable: true
      interval: 1000
    dns:
      enable: true
`

const tcpBasicConfig = `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tcp"
spec:
  parser:
    tcp:
      enable: true
`

type TCPCommon struct {
	suite.Suite
	useCLI          bool
	switches        []cli.SwitchSettings
	doneWG, readyWG sync.WaitGroup
	ctx             context.Context
	cancel          context.CancelFunc
}

type TCPBasic struct {
	TCPCommon
}

func TestTCPBasic(t *testing.T) {
	suite.Run(t, new(TCPBasic))
}

func TestTCPBasicCLI(t *testing.T) {
	suite.Run(t, new(TCPBasic{useCLI: true}))
}

func TestTCPPolicy(t *testing.T) {
	enterprisepolicytest.DoObserverTest(t, "layer3-tcp", nil)
}

func TestTCPCLI(t *testing.T) {
	enterprisepolicytest.DoObserverTest(t, "layer3-tcp-no-policy", nil)
}

func (suite *TCPBasic) SetupSuite() {
	suite.ctx, suite.cancel = context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	suite.startExistingTCPServices()

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
	obs := enterpriseoth.GetNoConfigObserver(suite.T(), suite.ctx, true)
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

func (suite *TCPBasic) HandleStats(_ string, stats *suite.SuiteInformation) {
	if stats.Passed() {
		osstestutils.DoneWithExportFile(suite.T())
	}
}

func (suite *TCPBasic) TearDownSuite() {
	suite.cancel()
	suite.stopExistingTCPServices()
	cli.RevertSwitchesConfig(suite.switches)
}

var (
	cmdServerTCP8082, cmdServerTCP8082V6, cmdServerTCP8083, cmdServerTCP8083V6, cmdServerTCP8094, cmdServerTCP8094V6 *exec.Cmd
	stdoutTCP8083, stdoutTCP8083V6                                                                                   io.ReadCloser
)

func (suite *TCPBasic) startExistingTCPServices() {
	nc := getNCCommand(suite.T(), "nc.openbsd")
	var err error

	cmdServerTCP8082 = exec.Command(nc, "-nvlp", "8082", "-s", "0.0.0.0")
	suite.Assert().NoError(cmdServerTCP8082.Start())
	cmdServerTCP8083 = exec.Command(nc, "-nvlp", "8083", "-s", "0.0.0.0")
	stdoutTCP8083, err = cmdServerTCP8083.StdoutPipe()
	suite.Assert().NoError(err)
	suite.Assert().NoError(cmdServerTCP8083.Start())
	cmdServerTCP8082V6 = exec.Command(nc, "-6nvlp", "8082", "-s", "::")
	suite.Assert().NoError(cmdServerTCP8082V6.Start())
	cmdServerTCP8083V6 = exec.Command(nc, "-6nvlp", "8083", "-s", "::")
	stdoutTCP8083V6, err = cmdServerTCP8083V6.StdoutPipe()
	suite.Assert().NoError(err)
	suite.Assert().NoError(cmdServerTCP8083V6.Start())

	path, err := os.Getwd()
	if err != nil {
		suite.T().Fail()
	}
	/* Start server in '/' before creating observer */
	os.Chdir("/")
	cmdServerTCP8094 = exec.Command(nc, "-nvlp", "8094", "-s", "0.0.0.0")
	suite.Assert().NoError(cmdServerTCP8094.Start())
	cmdServerTCP8094V6 = exec.Command(nc, "-6nvlp", "8094", "-s", "::")
	suite.Assert().NoError(cmdServerTCP8094V6.Start())
	os.Chdir(path)

	err = waitForSocketToListen(suite.T(), net.ParseIP("0.0.0.0"), 8082, syscall.IPPROTO_TCP, syscall.AF_INET)
	suite.Assert().NoError(err)
	err = waitForSocketToListen(suite.T(), net.ParseIP("0.0.0.0"), 8083, syscall.IPPROTO_TCP, syscall.AF_INET)
	suite.Assert().NoError(err)
	err = waitForSocketToListen(suite.T(), net.ParseIP("::"), 8082, syscall.IPPROTO_TCP, syscall.AF_INET6)
	suite.Assert().NoError(err)
	err = waitForSocketToListen(suite.T(), net.ParseIP("::"), 8083, syscall.IPPROTO_TCP, syscall.AF_INET6)
	suite.Assert().NoError(err)
	err = waitForSocketToListen(suite.T(), net.ParseIP("0.0.0.0"), 8094, syscall.IPPROTO_TCP, syscall.AF_INET)
	suite.Assert().NoError(err)
	err = waitForSocketToListen(suite.T(), net.ParseIP("::"), 8094, syscall.IPPROTO_TCP, syscall.AF_INET6)
	suite.Assert().NoError(err)
}

func (suite *TCPBasic) stopExistingTCPServices() {
	killAndWaitCommand(suite.T(), cmdServerTCP8082)
	killAndWaitCommand(suite.T(), cmdServerTCP8083)
	killAndWaitCommand(suite.T(), cmdServerTCP8082V6)
	killAndWaitCommand(suite.T(), cmdServerTCP8083V6)
	killAndWaitCommand(suite.T(), cmdServerTCP8094)
	killAndWaitCommand(suite.T(), cmdServerTCP8094V6)
}

func (suite *TCPBasic) TestExecEventClone4() {
	if runtime.GOARCH != "amd64" && !kernels.MinKernelVersion("5.8.0") {
		suite.T().Skip("Test requires amd64 or kernel >=5.8")
	}

	orig := "nc.openbsd"
	server := orig
	client := server
	if _, err := exec.LookPath(server); err != nil {
		server = "nc.openbsd"
		client = server

		if _, err := exec.LookPath(server); err != nil {
			suite.T().Fatalf("Binary server=%q,client=%q doesn't exist on host machine, cannot continue",
				server, client)
		}

		suite.T().Logf("Using server=%v,client=%v instead of original programs (server=%v,client=%v)",
			server, client, orig, orig)
	}

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncSrvChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-nvlp 8081 -s 0.0.0.0"))

	ncCliChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(client)).
		WithArguments(sm.Full("127.0.0.1 8081"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("serverExec").
			WithProcess(ncSrvChecker).
			WithParent(selfChecker),
		ec.NewProcessListenChecker("serverListen").
			WithProcess(ncSrvChecker).
			WithParent(selfChecker).
			WithIp(sm.Full("0.0.0.0")).
			WithPort(8081).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessExecChecker("clientExec").
			WithProcess(ncCliChecker).
			WithParent(selfChecker),
		ec.NewProcessConnectChecker("clientConnect").
			WithProcess(ncCliChecker).
			WithParent(selfChecker).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithDestinationPort(8081).
			WithProtocol(tetragon.SocketProtocol_TCP),
	)

	suite.readyWG.Wait()
	cmdServer := exec.Command(server, "-nvlp", "8081", "-s", "0.0.0.0")
	stdout, err := cmdServer.StdoutPipe()
	suite.Assert().NoError(err)
	suite.Assert().NoError(cmdServer.Start())
	err = waitForSocketToListen(suite.T(), net.ParseIP("0.0.0.0"), 8081, syscall.IPPROTO_TCP, syscall.AF_INET)
	suite.Assert().NoError(err)
	cmdClient := exec.Command(client, "127.0.0.1", "8081")
	stdin, err := cmdClient.StdinPipe()
	suite.Assert().NoError(err)
	suite.Assert().NoError(cmdClient.Start())

	sendData(suite.T(), stdin, "hello")
	waitForData(suite.T(), stdout, "hello")

	err = jsonchecker.JsonTestCheck(suite.T(), checker)
	suite.Assert().NoError(err)

	killAndWaitCommand(suite.T(), cmdServer)
	killAndWaitCommand(suite.T(), cmdClient)
}

func (suite *TCPBasic) TestExistingListenEvent4() {
	if runtime.GOARCH != "amd64" && !kernels.MinKernelVersion("5.8.0") {
		suite.T().Skip("Test requires amd64 or kernel >=5.8")
	}

	server := getNCCommand(suite.T(), "nc.openbsd")

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-nvlp 8082 -s 0.0.0.0"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("ncExec").
			WithProcess(ncChecker).
			WithParent(selfChecker),
		ec.NewProcessListenChecker("ncListen").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithIp(sm.Full("0.0.0.0")).
			WithPort(8082).
			WithProtocol(tetragon.SocketProtocol_TCP),
	)

	suite.readyWG.Wait()
	killAndWaitCommand(suite.T(), cmdServerTCP8082)

	err := jsonchecker.JsonTestCheck(suite.T(), checker)
	suite.Assert().NoError(err)
}

func (suite *TCPBasic) TestExistingAcceptEvent4() {
	if runtime.GOARCH != "amd64" && !kernels.MinKernelVersion("5.8.0") {
		suite.T().Skip("Test requires amd64 or kernel >=5.8")
	}

	server := getNCCommand(suite.T(), "nc.openbsd")
	client := server

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-nvlp 8083 -s 0.0.0.0"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("ncExec").
			WithProcess(ncChecker).
			WithParent(selfChecker),
		ec.NewProcessListenChecker("ncListen").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithIp(sm.Full("0.0.0.0")).
			WithPort(8083).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessAcceptChecker("ncAccept").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithSourcePort(8083).
			WithProtocol(tetragon.SocketProtocol_TCP),
	)

	suite.readyWG.Wait()
	cmdClient := exec.Command(client, "127.0.0.1", "8083")
	stdin, err := cmdClient.StdinPipe()
	suite.Assert().NoError(err)
	suite.Assert().NoError(cmdClient.Start())

	sendData(suite.T(), stdin, "hello")
	waitForData(suite.T(), stdoutTCP8083, "hello")

	err = jsonchecker.JsonTestCheck(suite.T(), checker)
	suite.Assert().NoError(err)

	killAndWaitCommand(suite.T(), cmdServerTCP8083)
	killAndWaitCommand(suite.T(), cmdClient)
}

func (suite *TCPBasic) TestExistingRootCWDListenEvent4() {
	if runtime.GOARCH != "amd64" && !kernels.MinKernelVersion("5.8.0") {
		suite.T().Skip("Test requires amd64 or kernel >=5.8")
	}

	server := getNCCommand(suite.T(), "nc.openbsd")

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-nvlp 8094 -s 0.0.0.0")).
		WithCwd(sm.Full("/"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("ncExec").
			WithProcess(ncChecker).
			WithParent(selfChecker),
		ec.NewProcessListenChecker("ncListen").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithIp(sm.Full("0.0.0.0")).
			WithPort(8094).
			WithProtocol(tetragon.SocketProtocol_TCP),
	)

	suite.readyWG.Wait()
	killAndWaitCommand(suite.T(), cmdServerTCP8094)

	err := jsonchecker.JsonTestCheck(suite.T(), checker)
	suite.Assert().NoError(err)
}

func (suite *TCPBasic) TestFailedConnectEvent6() {
	if runtime.GOARCH != "amd64" && !kernels.MinKernelVersion("5.8.0") {
		suite.T().Skip("Test requires amd64 or kernel >=5.8")
	}

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	curlChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix("curl")).
		WithArguments(sm.Full("[::1]"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("curlExec").
			WithProcess(curlChecker).
			WithParent(selfChecker),
		ec.NewProcessConnectChecker("curlConnect").
			WithProcess(curlChecker).
			WithParent(selfChecker).
			WithDestinationIp(sm.Full("::1")).
			WithDestinationPort(80).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessCloseChecker("curlClose").
			WithProcess(curlChecker).
			WithParent(selfChecker).
			WithDestinationIp(sm.Full("::1")).
			WithDestinationPort(80).
			WithProtocol(tetragon.SocketProtocol_TCP).
			WithSocketType(sm.Full("connect reset")),
	)

	observertesthelper.ExecWGCurl(&suite.readyWG, 10, "[::1]")
	err := jsonchecker.JsonTestCheck(suite.T(), checker)
	suite.Assert().NoError(err)
}

func (suite *TCPBasic) TestExecEventClone6() {
	if runtime.GOARCH != "amd64" && !kernels.MinKernelVersion("5.8.0") {
		suite.T().Skip("Test requires amd64 or kernel >=5.8")
	}

	orig := "nc.openbsd"
	server := orig
	client := server
	if _, err := exec.LookPath(server); err != nil {
		server = "nc.openbsd"
		client = server

		if _, err := exec.LookPath(server); err != nil {
			suite.T().Fatalf("Binary server=%q,client=%q doesn't exist on host machine, cannot continue",
				server, client)
		}

		suite.T().Logf("Using server=%v,client=%v instead of original programs (server=%v,client=%v)",
			server, client, orig, orig)
	}

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncSrvChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-6nvlp 8081 -s ::"))

	ncCliChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(client)).
		WithArguments(sm.Full("-6 ::1 8081"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("serverExec").
			WithProcess(ncSrvChecker).
			WithParent(selfChecker),
		ec.NewProcessListenChecker("serverListen").
			WithProcess(ncSrvChecker).
			WithParent(selfChecker).
			WithIp(sm.Full("::")).
			WithPort(8081).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessExecChecker("clientExec").
			WithProcess(ncCliChecker).
			WithParent(selfChecker),
		ec.NewProcessConnectChecker("clientConnect").
			WithProcess(ncCliChecker).
			WithParent(selfChecker).
			WithDestinationIp(sm.Full("::1")).
			WithDestinationPort(8081).
			WithProtocol(tetragon.SocketProtocol_TCP),
	)

	suite.readyWG.Wait()
	cmdServer := exec.Command(server, "-6nvlp", "8081", "-s", "::")
	stdout, err := cmdServer.StdoutPipe()
	suite.Assert().NoError(err)
	suite.Assert().NoError(cmdServer.Start())
	err = waitForSocketToListen(suite.T(), net.ParseIP("::"), 8081, syscall.IPPROTO_TCP, syscall.AF_INET6)
	suite.Assert().NoError(err)
	cmdClient := exec.Command(client, "-6", "::1", "8081")
	stdin, err := cmdClient.StdinPipe()
	suite.Assert().NoError(err)
	suite.Assert().NoError(cmdClient.Start())

	sendData(suite.T(), stdin, "hello")
	waitForData(suite.T(), stdout, "hello")

	err = jsonchecker.JsonTestCheck(suite.T(), checker)
	suite.Assert().NoError(err)

	killAndWaitCommand(suite.T(), cmdServer)
	killAndWaitCommand(suite.T(), cmdClient)
}

func (suite *TCPBasic) TestExistingListenEvent6() {
	if runtime.GOARCH != "amd64" && !kernels.MinKernelVersion("5.8.0") {
		suite.T().Skip("Test requires amd64 or kernel >=5.8")
	}

	server := getNCCommand(suite.T(), "nc.openbsd")

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-6nvlp 8082 -s ::"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("ncExec").
			WithProcess(ncChecker).
			WithParent(selfChecker),
		ec.NewProcessListenChecker("ncListen").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithIp(sm.Full("::")).
			WithPort(8082).
			WithProtocol(tetragon.SocketProtocol_TCP),
	)

	suite.readyWG.Wait()
	killAndWaitCommand(suite.T(), cmdServerTCP8082V6)

	err := jsonchecker.JsonTestCheck(suite.T(), checker)
	suite.Assert().NoError(err)
}

func (suite *TCPBasic) TestExistingAcceptEvent6() {
	if runtime.GOARCH != "amd64" && !kernels.MinKernelVersion("5.8.0") {
		suite.T().Skip("Test requires amd64 or kernel >=5.8")
	}

	server := getNCCommand(suite.T(), "nc.openbsd")
	client := server

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-6nvlp 8083 -s ::"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("ncExec").
			WithProcess(ncChecker).
			WithParent(selfChecker),
		ec.NewProcessListenChecker("ncListen").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithIp(sm.Full("::")).
			WithPort(8083).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessAcceptChecker("ncAccept").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("::1")).
			WithSourcePort(8083).
			WithProtocol(tetragon.SocketProtocol_TCP),
	)

	suite.readyWG.Wait()
	cmdClient := exec.Command(client, "-6", "::1", "8083")
	stdin, err := cmdClient.StdinPipe()
	suite.Assert().NoError(err)
	suite.Assert().NoError(cmdClient.Start())
	sendData(suite.T(), stdin, "hello")
	waitForData(suite.T(), stdoutTCP8083V6, "hello")

	err = jsonchecker.JsonTestCheck(suite.T(), checker)
	suite.Assert().NoError(err)

	killAndWaitCommand(suite.T(), cmdServerTCP8083V6)
	killAndWaitCommand(suite.T(), cmdClient)
}

func (suite *TCPBasic) TestExistingRootCWDListenEvent6() {
	if runtime.GOARCH != "amd64" && !kernels.MinKernelVersion("5.8.0") {
		suite.T().Skip("Test requires amd64 or kernel >=5.8")
	}

	server := getNCCommand(suite.T(), "nc.openbsd")

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-6nvlp 8094 -s ::")).
		WithCwd(sm.Full("/"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("ncExec").
			WithProcess(ncChecker).
			WithParent(selfChecker),
		ec.NewProcessListenChecker("ncListen").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithIp(sm.Full("::")).
			WithPort(8094).
			WithProtocol(tetragon.SocketProtocol_TCP),
	)

	suite.readyWG.Wait()

	killAndWaitCommand(suite.T(), cmdServerTCP8094V6)

	err := jsonchecker.JsonTestCheck(suite.T(), checker)
	suite.Assert().NoError(err)
}

func (suite *TCPBasic) TestListenAcceptClose6() {
	if runtime.GOARCH != "amd64" && !kernels.MinKernelVersion("5.8.0") {
		suite.T().Skip("Test requires amd64 or kernel >=5.8")
	}

	server := getNCCommand(suite.T(), "nc.openbsd")
	client := server

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-6nvlp 8085 -s ::"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("ncExec").
			WithProcess(ncChecker).
			WithParent(selfChecker),
		ec.NewProcessListenChecker("ncListen").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithIp(sm.Full("::")).
			WithPort(8085).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessAcceptChecker("ncAccept").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("::1")).
			WithSourcePort(8085).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessCloseChecker("ncClose").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("::")).
			WithSourcePort(8085).
			WithProtocol(tetragon.SocketProtocol_TCP).
			WithSocketType(sm.Full("listen")),
		// TODO: it would be good if we could also check the close event on
		// the accept socket, but it goes into TIME_WAIT and then
		// eventually close and I don't want to wait for it. So we need
		// some go way to close the sockets.
	)

	suite.readyWG.Wait()
	cmdServer := exec.Command(server, "-6nvlp", "8085", "-s", "::")
	stdout, err := cmdServer.StdoutPipe()
	suite.Assert().NoError(err)
	suite.Assert().NoError(cmdServer.Start())
	err = waitForSocketToListen(suite.T(), net.ParseIP("::"), 8085, syscall.IPPROTO_TCP, syscall.AF_INET6)
	suite.Assert().NoError(err)
	cmdClient := exec.Command(client, "-6", "::1", "8085")
	stdin, err := cmdClient.StdinPipe()
	suite.Assert().NoError(err)
	suite.Assert().NoError(cmdClient.Start())

	sendData(suite.T(), stdin, "hello")
	waitForData(suite.T(), stdout, "hello")

	killAndWaitCommand(suite.T(), cmdServer)
	killAndWaitCommand(suite.T(), cmdClient)

	// Wait for the sockets to close
	err = waitAndCheckForSocketsToClose(suite.T(), checker, net.ParseIP("::1"), 8085, syscall.IPPROTO_TCP, syscall.AF_INET)
	suite.Assert().NoError(err)
}

func (suite *TCPBasic) TestIOUringAcceptEvent() {
	if !utils.CGroupSKBAvailable() {
		suite.T().Skipf("This test requires CGroup/SKB, skipping")
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "x86_64" {
		suite.T().Skipf("Test seems to time out on ARM")
	}
	if !testutils.NetIOUringAvailable() {
		suite.T().Skipf("Net io_uring not available, skipping")
	}

	server := testutils.RepoRootPath("contrib/tester-progs/io_uring/tcp_iouring_server")
	client := getNCCommand(suite.T(), "nc.openbsd")

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncSrvChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server))

	ncCliChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(client)).
		WithArguments(sm.Full("127.0.0.1 8000"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("serverExec").
			WithProcess(ncSrvChecker).
			WithParent(selfChecker),
		ec.NewProcessExecChecker("clientExec").
			WithProcess(ncCliChecker).
			WithParent(selfChecker),
		ec.NewProcessAcceptChecker("serverAccept").
			WithProcess(ncSrvChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithSourcePort(8000).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessCloseChecker("serverClose").
			WithProcess(ncSrvChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithSourcePort(8000).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithProtocol(tetragon.SocketProtocol_TCP).
			WithSocketType(sm.Full("accept")).
			WithStats(ec.NewSocketStatsChecker().
				WithBytesSent(5).
				WithBytesReceived(5)),
	)

	suite.readyWG.Wait()
	cmdServer := exec.Command(server)
	serverOutput, err := cmdServer.StdoutPipe()
	suite.Require().NoError(err, "could not connect to server output pipe")
	cmdServer.Stderr = os.Stderr

	err = cmdServer.Start()
	suite.Require().NoError(err, "cannot start server")

	serverBuf := bufio.NewReader(serverOutput)
	var line []byte
	for string(line) != "Ready" {
		line, _, err = serverBuf.ReadLine()
		if err != nil {
			killAndWaitCommand(suite.T(), cmdServer)
			suite.T().Fatal(err)
		}
		if len(line) == 0 {
			killAndWaitCommand(suite.T(), cmdServer)
			suite.T().Fatal("received empty line from TCP server")
		}
		if strings.HasPrefix(string(line), "NotReady") {
			suite.T().Fatalf("TCP server failed to start: '%s'", string(line))
		}
	}

	serverPid := uint32(cmdServer.Process.Pid)
	logger.GetLogger().Info("Running", "ServerPid", serverPid)

	cmdClient := exec.Command(client, "127.0.0.1", "8000")
	stdin, err := cmdClient.StdinPipe()
	suite.Assert().NoError(err)
	suite.Assert().NoError(cmdClient.Start())
	_, err = stdin.Write([]byte("hello"))
	suite.Assert().NoError(err)

	err = jsonchecker.JsonTestCheck(suite.T(), checker)
	suite.Assert().NoError(err)

	killAndWaitCommand(suite.T(), cmdServer)
	killAndWaitCommand(suite.T(), cmdClient)
}

// FIXME: net io_uring test seems to time out on ARM.
func (suite *TCPBasic) TestIOUringConnectEvent() {
	if !utils.CGroupSKBAvailable() {
		suite.T().Skipf("This test requires CGroup/SKB, skipping")
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "x86_64" {
		suite.T().Skipf("Test seems to time out on ARM")
	}
	if !testutils.NetIOUringAvailable() {
		suite.T().Skipf("Net io_uring not available, skipping")
	}

	client := testutils.RepoRootPath("contrib/tester-progs/io_uring/tcp_iouring_client")
	server := getNCCommand(suite.T(), "nc.openbsd")

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncSrvChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-nvlp 8001"))

	ncCliChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(client))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("serverExec").
			WithProcess(ncSrvChecker).
			WithParent(selfChecker),
		ec.NewProcessExecChecker("clientExec").
			WithProcess(ncCliChecker).
			WithParent(selfChecker),
		ec.NewProcessConnectChecker("clientConnect").
			WithProcess(ncCliChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithDestinationPort(8001).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessCloseChecker("serverClose").
			WithProcess(ncCliChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithDestinationPort(8001).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithProtocol(tetragon.SocketProtocol_TCP).
			WithSocketType(sm.Full("connect")).
			WithStats(ec.NewSocketStatsChecker().
				WithBytesSent(5)),
	)

	suite.readyWG.Wait()
	cmdServer := exec.Command(server, "-nvlp", "8001")
	serverError, err := cmdServer.StderrPipe()
	suite.Require().NoError(err, "could not connect to server output pipe")
	cmdServer.Stdout = nil

	err = cmdServer.Start()
	suite.Require().NoError(err, "cannot start server")

	serverBuf := bufio.NewReader(serverError)
	var line []byte
	for string(line) != "Listening on 0.0.0.0 8001" {
		line, _, err = serverBuf.ReadLine()
		if err != nil {
			killAndWaitCommand(suite.T(), cmdServer)
			suite.T().Fatal(err)
		}
		if len(line) == 0 {
			killAndWaitCommand(suite.T(), cmdServer)
			suite.T().Fatal("received empty line from TCP server")
		}
	}

	serverPid := uint32(cmdServer.Process.Pid)
	logger.GetLogger().Info("Running", "ServerPid", serverPid)

	cmdClient := exec.Command(client)
	cmdClient.Stderr = os.Stderr
	cmdClient.Stdout = os.Stdout

	err = cmdClient.Start()
	suite.Require().NoError(err, "cannot start client")

	err = cmdClient.Wait()
	if err != nil {
		killAndWaitCommand(suite.T(), cmdServer)
		suite.T().Fatal(err)
	}

	err = jsonchecker.JsonTestCheck(suite.T(), checker)
	suite.Assert().NoError(err)

	killAndWaitCommand(suite.T(), cmdServer)
	killAndWaitCommand(suite.T(), cmdClient)
}
