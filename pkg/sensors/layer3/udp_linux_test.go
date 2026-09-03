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
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/matchers/durationmatcher"
	"github.com/cilium/tetragon/pkg/matchers/listmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors/config/confmap"
	osstestutils "github.com/cilium/tetragon/pkg/testutils"
	"github.com/cilium/tetragon/pkg/tracingpolicy"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"

	"github.com/cilium/tetragon/pkg/jsonchecker"

	enterpriseoth "github.com/isovalent/hubble-fgs/pkg/observer/observertesthelper"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3"
	"github.com/isovalent/hubble-fgs/pkg/sensors/networkWatermarksEvents"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
	"github.com/isovalent/hubble-fgs/pkg/testutils"
	cli "github.com/isovalent/hubble-fgs/pkg/testutils/cliswitches"
	enterprisepolicytest "github.com/isovalent/hubble-fgs/pkg/testutils/policytest"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"
	_ "github.com/isovalent/hubble-fgs/tests/policytests"

	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	//_ "github.com/isovalent/hubble-fgs/pkg/sensors/sockmap"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/isovalent/hubble-fgs/pkg/metrics/socketmetrics"
)

const udpConfigLegacy = `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "udp"
spec:
  parser:
    udp:
      enable: true
      cgroup: true
      statsInterval: 20
      deleteIdleSocketInterval: 60
      burst:
        enable: true
        windowSize: 1000
        triggerPercent: 50
    burstExitGen:
      enable: true
      interval: 1000
    dns:
      enable: true
      ports: [53]
`

const udpConfig = `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "udp"
spec:
  parser:
    udp:
      enable: true
      cgroup: true
      statsInterval: 20
      deleteIdleSocketInterval: 60
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
      ports: [53]
`

const udpConfigWithoutDnsQuestions = `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "udp"
spec:
  parser:
    udp:
      enable: true
    dns:
      enable: true
      ports: [53]
`

const udpConfigWithDnsQuestions = `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "udp"
spec:
  parser:
    udp:
      enable: true
    dns:
      enable: true
      ports: [53]
      reportQuestions: true
`

const udpConfigDisableClose = `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "udp"
spec:
  parser:
    dns:
      enable: true
      ports: [53]
    udp:
      enable: true
      cgroup: true
      statsInterval: 20
      deleteIdleSocketInterval: 60
      disableEvents:
        disableClose: `

const udpConfigDisableListen = `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "udp"
spec:
  parser:
    dns:
      enable: true
      ports: [53]
    udp:
      enable: true
      cgroup: true
      statsInterval: 20
      deleteIdleSocketInterval: 60
      disableEvents:
        disableListen: `

const udpConfigBasic = `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "udp"
spec:
  parser:
    udp:
      enable: true
      cgroup: true
`

const udpBasicConfig = `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "udp"
spec:
  parser:
    udp:
      enable: true
      cgroup: true
      statsInterval: 2
`

const UDPBUFSIZE, UDPBUFVAR = 1024, 256
const udpHostname = "127.0.0.1"
const udpPortno = 31337
const udpProtocol = "udp4"

type multicastTest int

const (
	multicastTestLSEGConnID multicastTest = iota
	multicastTestLSEGConnIDCLI
	multicastTestLSEGSeq
	multicastTestLSEGSeqCLI
	multicastTestLSEGSample
	multicastTestLSEGSampleCLI
	multicastTestRTPConnID
	multicastTestRTPConnIDCLI
	multicastTestRTPSeq
	multicastTestRTPSeqCLI
	multicastTestRTPSample
	multicastTestRTPSampleCLI
)

func runUdpServer() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		if sig == syscall.SIGTERM {
			os.Exit(0)
		}
	}()

	conn, err := net.ListenPacket(udpProtocol, fmt.Sprintf("%s:%d", udpHostname, udpPortno))
	if err != nil {
		fmt.Printf("NotReady: %s", err)
		panic(err)
	}
	buf := make([]byte, 2*UDPBUFSIZE)
	fmt.Printf("Ready\n")
	for {
		_, _, err = conn.ReadFrom(buf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR reading from socket\n")
			panic(err)
		}
	}
}

func udpSendData(socket net.Conn, buf []byte) {
	bufLen := rand.Intn(UDPBUFVAR) - (UDPBUFVAR / 2) + UDPBUFSIZE
	_, err := socket.Write(buf[0:bufLen])
	if err != nil {
		fmt.Printf("ERROR writing to socket\n")
		panic(err)
	}
}

func runUdpWatermarksClient() {
	baselineRate := 5
	burstRate := 20
	baselineDuration := 1
	burstDuration := 1
	numBursts := 5

	baselineWait := time.Duration(1000000 / baselineRate)
	burstWait := time.Duration(1000000 / burstRate)

	randFile, err := os.Open("/dev/urandom")
	if err != nil {
		fmt.Printf("ERROR opening urandom\n")
		panic(err)
	}

	buf := make([]byte, UDPBUFSIZE+UDPBUFVAR)
	randReader := bufio.NewReader(randFile)
	_, err = randReader.Read(buf)
	if err != nil {
		fmt.Printf("ERROR reading urandom\n")
		panic(err)
	}
	randFile.Close()

	socket, err := net.Dial(udpProtocol, net.JoinHostPort(udpHostname, fmt.Sprintf("%d", udpPortno)))
	if err != nil {
		fmt.Printf("ERROR dialing socket\n")
		panic(err)
	}

	for range numBursts {
		for range baselineDuration * baselineRate {
			udpSendData(socket, buf)
			time.Sleep(baselineWait * time.Microsecond)
		}
		for range burstDuration * burstRate {
			udpSendData(socket, buf)
			time.Sleep(burstWait * time.Microsecond)
		}
	}
}

func testUdpWatermarks(t *testing.T, CLISwitches, legacy bool) {
	// timing related tests are unreliable currently. In lieu of a solution, let's
	// disable these tests.
	t.Skipf("Test disabled due to unreliable timing in CI")
	if !utils.CGroupSKBAvailable() {
		t.Skipf("This test requires CGroup/SKB, skipping")
	}

	if runtime.GOARCH != "amd64" && !kernels.MinKernelVersion("5.8.0") {
		t.Skip("Test requires amd64 or kernel >=5.8")
	}

	clientProcess := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary)).
		WithArguments(sm.Full("-udpWatermarksClient"))

	serverProcess := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary)).
		WithArguments(sm.Full("-udpServer"))

	var checker *ec.UnorderedEventChecker

	// CLISwitches implies !legacy
	if legacy && !CLISwitches {
		checker = ec.NewUnorderedEventChecker(
			ec.NewProcessExecChecker("clientExec").
				WithProcess(clientProcess),
			ec.NewProcessNetworkBurstChecker("egressStart").
				WithProcess(clientProcess).
				WithProtocol(sm.Full("UDP")).
				WithDirection(sm.Full("egress")).
				WithBurstState(sm.Full("start")),
			ec.NewProcessNetworkBurstChecker("egressEnd").
				WithProcess(clientProcess).
				WithProtocol(sm.Full("UDP")).
				WithDirection(sm.Full("egress")).
				WithBurstState(sm.Full("end")),
			ec.NewProcessExecChecker("serverStart").
				WithProcess(serverProcess),
			ec.NewProcessNetworkBurstChecker("ingressStart").
				WithProcess(serverProcess).
				WithProtocol(sm.Full("UDP")).
				WithDirection(sm.Full("ingress")).
				WithBurstState(sm.Full("start")),
			ec.NewProcessNetworkBurstChecker("ingressEnd").
				WithProcess(serverProcess).
				WithProtocol(sm.Full("UDP")).
				WithDirection(sm.Full("ingress")).
				WithBurstState(sm.Full("end")),
			ec.NewProcessCloseChecker("serverClose").
				WithProcess(serverProcess).
				WithDuration(durationmatcher.Between(&durationmatcher.Duration{Duration: time.Duration(1 * time.Second)},
					&durationmatcher.Duration{Duration: time.Duration(20 * time.Second)})),
			ec.NewProcessExitChecker("serverExit").
				WithProcess(serverProcess),
		)
	} else {
		checker = ec.NewUnorderedEventChecker(
			ec.NewProcessExecChecker("clientExec").
				WithProcess(clientProcess),
			ec.NewProcessNetworkWatermarkChecker("burstEgressStart").
				WithProcess(clientProcess).
				WithProtocol(sm.Full("UDP")).
				WithWatermarksType(sm.Full("burst")).
				WithDirection(sm.Full("egress")).
				WithWatermarksState(sm.Full("start")),
			ec.NewProcessNetworkWatermarkChecker("burstEgressEnd").
				WithProcess(clientProcess).
				WithProtocol(sm.Full("UDP")).
				WithWatermarksType(sm.Full("burst")).
				WithDirection(sm.Full("egress")).
				WithWatermarksState(sm.Full("end")),
			ec.NewProcessNetworkWatermarkChecker("dipEgressStart").
				WithProcess(clientProcess).
				WithProtocol(sm.Full("UDP")).
				WithWatermarksType(sm.Full("dip")).
				WithDirection(sm.Full("egress")).
				WithWatermarksState(sm.Full("start")),
			ec.NewProcessNetworkWatermarkChecker("dipEgressEnd").
				WithProcess(clientProcess).
				WithProtocol(sm.Full("UDP")).
				WithWatermarksType(sm.Full("dip")).
				WithDirection(sm.Full("egress")).
				WithWatermarksState(sm.Full("end")),
			ec.NewProcessExecChecker("serverStart").
				WithProcess(serverProcess),
			ec.NewProcessNetworkWatermarkChecker("burstIngressStart").
				WithProcess(serverProcess).
				WithProtocol(sm.Full("UDP")).
				WithWatermarksType(sm.Full("burst")).
				WithDirection(sm.Full("ingress")).
				WithWatermarksState(sm.Full("start")),
			ec.NewProcessNetworkWatermarkChecker("burstIngressEnd").
				WithProcess(serverProcess).
				WithProtocol(sm.Full("UDP")).
				WithWatermarksType(sm.Full("burst")).
				WithDirection(sm.Full("ingress")).
				WithWatermarksState(sm.Full("end")),
			ec.NewProcessNetworkWatermarkChecker("dipIngressStart").
				WithProcess(serverProcess).
				WithProtocol(sm.Full("UDP")).
				WithWatermarksType(sm.Full("dip")).
				WithDirection(sm.Full("ingress")).
				WithWatermarksState(sm.Full("start")),
			ec.NewProcessNetworkWatermarkChecker("dipIngressEnd").
				WithProcess(serverProcess).
				WithProtocol(sm.Full("UDP")).
				WithWatermarksType(sm.Full("dip")).
				WithDirection(sm.Full("ingress")).
				WithWatermarksState(sm.Full("end")),
			ec.NewProcessCloseChecker("serverClose").
				WithProcess(serverProcess).
				WithDuration(durationmatcher.Between(&durationmatcher.Duration{Duration: time.Duration(1 * time.Second)},
					&durationmatcher.Duration{Duration: time.Duration(20 * time.Second)})),
			ec.NewProcessExitChecker("serverExit").
				WithProcess(serverProcess),
		)
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	if CLISwitches {
		require.NoError(t, cli.SetSwitches(t, []cli.SwitchSettings{
			{KeyPtr: &enterpriseOption.Config.Layer3CLIEnable, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableNetworkEvents, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableUDP, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableUDPCGroup, Value: true},
			{KeyPtr: &enterpriseOption.Config.UDPStatsInterval, Value: 20 * time.Second},
			{KeyPtr: &enterpriseOption.Config.UDPIdleSocketTimeout, Value: time.Minute},
			{KeyPtr: &enterpriseOption.Config.EnableUDPWatermarks, Value: true},
			{KeyPtr: &enterpriseOption.Config.UDPWatermarksWindowSizeMs, Value: uint32(1000)},
			{KeyPtr: &enterpriseOption.Config.UDPWatermarksBurstTriggerPercent, Value: uint32(50)},
			{KeyPtr: &enterpriseOption.Config.UDPWatermarksDipTriggerPercent, Value: uint32(10)},
			{KeyPtr: &enterpriseOption.Config.EnableNetworkWatermarksExitGen, Value: true},
			{KeyPtr: &enterpriseOption.Config.NetworkWatermarksExitGenInterval, Value: 1000 * time.Millisecond},
		}))
	}

	obs := enterpriseoth.GetNoConfigObserver(t, ctx, true)
	require.NoError(t, layer3.StartLayer3Progs(ctx, nil))

	if !CLISwitches {
		var configYaml string
		if legacy {
			configYaml = udpConfigLegacy
		} else {
			configYaml = udpConfig
		}
		tp, err := tracingpolicy.FromYAML(configYaml)
		require.NoError(t, err)
		err = observer.GetSensorManager().AddTracingPolicy(ctx, tp)
		require.NoError(t, err)
	}
	option.Config.UsePerfRingBuffer = true
	confmap.UpdateTgRuntimeConf(bpf.MapPrefixPath(), os.Getpid())
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	serverCmd := exec.Command(os.Args[0], "-udpServer")
	serverOutput, err := serverCmd.StdoutPipe()
	require.NoError(t, err, "could not connect to server output pipe")
	serverCmd.Stderr = os.Stderr

	err = serverCmd.Start()
	require.NoError(t, err, "cannot start server")

	serverBuf := bufio.NewReader(serverOutput)
	var line []byte
	for string(line) != "Ready" {
		line, _, err = serverBuf.ReadLine()
		if err != nil {
			killAndWaitCommand(t, serverCmd)
			t.Fatal(err)
		}
		if len(line) == 0 {
			killAndWaitCommand(t, serverCmd)
			t.Fatal("received empty line from UDP server")
		}
		if strings.HasPrefix(string(line), "NotReady") {
			t.Fatalf("UDP server failed to start: '%s'", string(line))
		}
	}

	serverPid := uint32(serverCmd.Process.Pid)

	watermarksMapFile := filepath.Join(bpf.MapPrefixPath(), networkWatermarksEvents.ProcessNetworkWatermarksMapName)
	m, err := ebpf.LoadPinnedMap(watermarksMapFile, nil)
	require.NoError(t, err, "cannot open map file")
	defer m.Close()
	processKey := &networkWatermarksEvents.ProcessNetworkWatermarksKey{Key: networkWatermarksEvents.PidToWatermarksKey(serverPid, syscall.IPPROTO_UDP, 0)}
	var processValue networkWatermarksEvents.ProcessNetworkWatermarksValue
	err = m.Lookup(processKey, &processValue)
	require.Error(t, err, "server process in watermarks map before traffic")

	clientCmd := exec.Command(os.Args[0], "-udpWatermarksClient")
	clientCmd.Stdout = os.Stderr
	clientCmd.Stderr = os.Stderr
	err = clientCmd.Run()
	require.NoError(t, err, "cannot start client")

	err = m.Lookup(processKey, &processValue)
	require.NoError(t, err, "server process must be in watermarks map")

	killAndWaitCommand(t, serverCmd)

	// the burst map record is sure to be removed after exit event is
	// received, let's wait for that and do the lookup check after

	err = jsonchecker.JsonTestCheck(t, checker)
	require.NoError(t, err)

	err = m.Lookup(processKey, &processValue)
	require.Error(t, err, "server process in watermarks map after exit")

	killAndWaitCommand(t, clientCmd)
}

func TestUdpBurst(t *testing.T) {
	testUdpWatermarks(t, false, true)
}

func TestUdpWatermarks(t *testing.T) {
	testUdpWatermarks(t, false, false)
}

func TestUdpWatermarksCLI(t *testing.T) {
	testUdpWatermarks(t, true, false)
}

func configureDisableSwitchesAndConfig(t *testing.T, CLISwitches bool, disableConnect bool, disableListen bool, disableClose bool, disableStats bool) string {
	eventDisableConfig := `
      disableEvents:
`
	eventDisableConfig += "\n        disableConnect: " + strconv.FormatBool(disableConnect)
	eventDisableConfig += "\n        disableListen: " + strconv.FormatBool(disableListen)
	eventDisableConfig += "\n        disableClose: " + strconv.FormatBool(disableClose)
	eventDisableConfig += "\n        disableStats: " + strconv.FormatBool(disableStats)

	if CLISwitches {
		require.NoError(t, cli.SetSwitches(t, []cli.SwitchSettings{
			{KeyPtr: &enterpriseOption.Config.Layer3CLIEnable, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableNetworkEvents, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableUDP, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableUDPCGroup, Value: utils.CGroupSKBAvailable()},
			{KeyPtr: &enterpriseOption.Config.UDPStatsInterval, Value: 2 * time.Second},
			{KeyPtr: &enterpriseOption.Config.UDPDisableListenEvents, Value: disableListen},
			{KeyPtr: &enterpriseOption.Config.UDPDisableConnectEvents, Value: disableConnect},
			{KeyPtr: &enterpriseOption.Config.UDPDisableStatsEvents, Value: disableStats},
			{KeyPtr: &enterpriseOption.Config.UDPDisableCloseEvents, Value: disableClose},
		}))
		return ""
	}
	return udpBasicConfig + eventDisableConfig
}

type UDPBasic struct {
	suite.Suite
	useCLI          bool
	switches        []cli.SwitchSettings
	doneWG, readyWG sync.WaitGroup
	ctx             context.Context
	cancel          context.CancelFunc
}

func TestUDPBasic(t *testing.T) {
	suite.Run(t, new(UDPBasic))
}

func TestUDPBasicCLI(t *testing.T) {
	suite.Run(t, &UDPBasic{useCLI: true})
}

func (suite *UDPBasic) SetupSuite() {
	suite.ctx, suite.cancel = context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)

	suite.startExistingUDPServices()

	if suite.useCLI {
		var err error
		suite.switches, err = cli.SetConfigFromSwitches([]cli.SwitchSettings{
			{KeyPtr: &enterpriseOption.Config.Layer3CLIEnable, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableNetworkEvents, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableUDP, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableUDPCGroup, Value: utils.CGroupSKBAvailable()},
			{KeyPtr: &enterpriseOption.Config.EnableUDPMetrics, Value: true},
			{KeyPtr: &enterpriseOption.Config.UDPStatsInterval, Value: 2 * time.Second},
		})
		suite.Require().NoError(err)
	}
	obs := enterpriseoth.GetNoConfigObserver(suite.T(), suite.ctx, true)
	suite.Require().NoError(layer3.StartLayer3Progs(suite.ctx, nil))

	if !suite.useCLI {
		tp, err := tracingpolicy.FromYAML(udpBasicConfig)
		suite.Require().NoError(err)
		err = observer.GetSensorManager().AddTracingPolicy(suite.ctx, tp)
		suite.Require().NoError(err)
	}

	option.Config.UsePerfRingBuffer = true
	confmap.UpdateTgRuntimeConf(bpf.MapPrefixPath(), os.Getpid())
	observertesthelper.LoopEvents(suite.ctx, suite.T(), &suite.doneWG, &suite.readyWG, obs)
}

func (suite *UDPBasic) HandleStats(_ string, stats *suite.SuiteInformation) {
	if stats.Passed() {
		osstestutils.DoneWithExportFile(suite.T())
	}
}

func (suite *UDPBasic) TearDownSuite() {
	suite.cancel()
	suite.stopExistingUDPServices()
	cli.RevertSwitchesConfig(suite.switches)
}

var (
	cmdServerUDP8981, cmdServerUDP8981V6 *exec.Cmd
	stdoutUDP8981, stdoutUDP8981V6       io.ReadCloser
)

func (suite *UDPBasic) startExistingUDPServices() {
	nc := getNCCommand(suite.T(), "nc.openbsd")
	var err error

	cmdServerUDP8981 = exec.Command(nc, "-unvlp", "8981", "-s", "0.0.0.0")
	stdoutUDP8981, err = cmdServerUDP8981.StdoutPipe()
	suite.Assert().NoError(err)
	suite.Assert().NoError(cmdServerUDP8981.Start())
	cmdServerUDP8981V6 = exec.Command(nc, "-6unvlp", "8981", "-s", "::")
	stdoutUDP8981V6, err = cmdServerUDP8981V6.StdoutPipe()
	suite.Assert().NoError(err)
	suite.Assert().NoError(cmdServerUDP8981V6.Start())
	err = waitForSocketToListen(suite.T(), net.ParseIP("0.0.0.0"), 8981, syscall.IPPROTO_UDP, syscall.AF_INET)
	suite.Assert().NoError(err)
	err = waitForSocketToListen(suite.T(), net.ParseIP("::"), 8981, syscall.IPPROTO_UDP, syscall.AF_INET6)
	suite.Assert().NoError(err)
}

func (suite *UDPBasic) stopExistingUDPServices() {
	killAndWaitCommand(suite.T(), cmdServerUDP8981)
	killAndWaitCommand(suite.T(), cmdServerUDP8981V6)
}

func (suite *UDPBasic) TestUdpConnectEvent4() {
	if runtime.GOARCH != "amd64" && !kernels.MinKernelVersion("5.8.0") {
		suite.T().Skip("Test requires amd64 or kernel >=5.8")
	}

	server := getNCCommand(suite.T(), "nc.openbsd")
	client := server

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncSrvChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-unvlp 8081 -s 0.0.0.0"))

	ncCliChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(client)).
		WithArguments(sm.Full("-u 127.0.0.1 8081"))

	clientStatsChecker := ec.NewProcessSockStatsChecker("clientStats").
		WithProcess(ncCliChecker).
		WithParent(selfChecker).
		WithSocket(ec.NewSockInfoChecker().
			WithProtocol(tetragon.SocketProtocol_UDP).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithDestinationPort(8081))

	serverStatsChecker := ec.NewProcessSockStatsChecker("serverStats").
		WithProcess(ncSrvChecker).
		WithParent(selfChecker).
		WithSocket(ec.NewSockInfoChecker().
			WithProtocol(tetragon.SocketProtocol_UDP).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithSourcePort(8081))

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
		ec.NewProcessConnectChecker("serverConnect").
			WithProcess(ncSrvChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithSourcePort(8081).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithProtocol(tetragon.SocketProtocol_UDP),
		ec.NewProcessCloseChecker("serverClose").
			WithProcess(ncSrvChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithSourcePort(8081).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithProtocol(tetragon.SocketProtocol_UDP),
		ec.NewProcessCloseChecker("clientClose").
			WithProcess(ncCliChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithDestinationPort(8081).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithProtocol(tetragon.SocketProtocol_UDP),
		clientStatsChecker,
		serverStatsChecker,
	)

	// We need to check sockstats using a custom stateful checker since stats events can
	// be split up and so checking the individual events won't work. We need to instead
	// keep a cumulative count of the stats we have seen and compare them to expected
	// totals.
	var clientBytesSent uint64
	var clientSegsOut uint32
	var serverBytesReceived uint64
	var serverSegsIn uint32
	statsChecker := &ec.FnEventChecker{
		NextCheckFn: func(event_ ec.Event, _ *slog.Logger) (bool, error) {
			event, ok := event_.(*tetragon.ProcessSockStats)
			if !ok {
				return false, fmt.Errorf("event is not a sockstats event")
			}

			if event.Stats == nil {
				return false, fmt.Errorf("event has no stats field")
			}

			if clientStatsChecker.Check(event) == nil {
				clientBytesSent += event.Stats.BytesSent
				clientSegsOut += event.Stats.SegsOut
				return false, nil
			}

			if serverStatsChecker.Check(event) == nil {
				serverBytesReceived += event.Stats.BytesReceived
				serverSegsIn += event.Stats.SegsIn
				return false, nil
			}

			return false, fmt.Errorf("sockstats event is neither from client nor server")
		},
		FinalCheckFn: func(_ *slog.Logger) error {
			defer func() {
				clientBytesSent = 0
				clientSegsOut = 0
				serverBytesReceived = 0
				serverSegsIn = 0
			}()

			if clientBytesSent != 5 {
				return fmt.Errorf("Unexecpected clientBytesSent, wanted 5, got %d", clientBytesSent)
			}

			if clientSegsOut != 1 {
				return fmt.Errorf("Unexecpected clientSegsOut, wanted 1, got %d", clientSegsOut)
			}

			if serverBytesReceived != 5 {
				return fmt.Errorf("Unexecpected serverBytesReceived, wanted 5, got %d", serverBytesReceived)
			}

			if serverSegsIn != 1 {
				return fmt.Errorf("Unexecpected serverSegsIn, wanted 1, got %d", serverSegsIn)
			}

			return nil
		},
	}

	suite.readyWG.Wait()
	cmdServer := exec.Command(server, "-unvlp", "8081", "-s", "0.0.0.0")
	stdout, err := cmdServer.StdoutPipe()
	suite.Assert().NoError(err)
	suite.Assert().NoError(cmdServer.Start())
	err = waitForSocketToListen(suite.T(), net.IPv4(0, 0, 0, 0), 8081, syscall.IPPROTO_UDP, syscall.AF_INET)
	suite.Assert().NoError(err)

	cmdClient := exec.Command(client, "-u", "127.0.0.1", "8081")
	stdin, err := cmdClient.StdinPipe()
	suite.Assert().NoError(err)
	suite.Assert().NoError(cmdClient.Start())
	sendData(suite.T(), stdin, "hello")
	waitForData(suite.T(), stdout, "hello")

	killAndWaitCommand(suite.T(), cmdClient)
	killAndWaitCommand(suite.T(), cmdServer)

	err = jsonchecker.JsonTestCheck(suite.T(), checker)
	suite.Assert().NoError(err)

	err = jsonchecker.JsonTestCheck(suite.T(), statsChecker)
	suite.Assert().NoError(err)
}

func (suite *UDPBasic) TestListenEvent4() {
	if runtime.GOARCH != "amd64" && !kernels.MinKernelVersion("5.8.0") {
		suite.T().Skip("Test requires amd64 or kernel >=5.8")
	}

	server := getNCCommand(suite.T(), "nc.openbsd")

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncSrvChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-unvlp 8082 -s 0.0.0.0"))

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
			WithPort(8082).
			WithProtocol(tetragon.SocketProtocol_UDP),
	)

	suite.readyWG.Wait()
	cmdServer := exec.Command(server, "-unvlp", "8082", "-s", "0.0.0.0")
	suite.Assert().NoError(cmdServer.Start())
	err := waitForSocketToListen(suite.T(), net.ParseIP("0.0.0.0"), 8082, syscall.IPPROTO_UDP, syscall.AF_INET)
	suite.Assert().NoError(err)

	err = jsonchecker.JsonTestCheck(suite.T(), checker)
	suite.Assert().NoError(err)

	killAndWaitCommand(suite.T(), cmdServer)
}

func TestUDPCLISwitch(t *testing.T) {
	if !utils.CGroupSKBAvailable() {
		t.Skipf("This test requires CGroup/SKB, skipping")
	}

	if runtime.GOARCH != "amd64" && !kernels.MinKernelVersion("5.8.0") {
		t.Skip("Test requires amd64 or kernel >=5.8")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	require.NoError(t, cli.SetSwitches(t, []cli.SwitchSettings{
		{KeyPtr: &enterpriseOption.Config.Layer3CLIEnable, Value: true},
		{KeyPtr: &enterpriseOption.Config.EnableNetworkEvents, Value: true},
		{KeyPtr: &enterpriseOption.Config.EnableUDP, Value: true},
		{KeyPtr: &enterpriseOption.Config.EnableUDPCGroup, Value: utils.CGroupSKBAvailable()},
	}))

	server := getNCCommand(t, "nc.openbsd")

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncSrvChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-unvlp 8083 -s 0.0.0.0"))

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
			WithPort(8083).
			WithProtocol(tetragon.SocketProtocol_UDP),
	)

	obs := enterpriseoth.GetNoConfigObserver(t, ctx, true)
	require.NoError(t, layer3.StartLayer3Progs(ctx, nil))
	option.Config.UsePerfRingBuffer = true
	confmap.UpdateTgRuntimeConf(bpf.MapPrefixPath(), os.Getpid())
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdServer := exec.Command(server, "-unvlp", "8083", "-s", "0.0.0.0")
	assert.NoError(t, cmdServer.Start())
	err := waitForSocketToListen(t, net.ParseIP("0.0.0.0"), 8083, syscall.IPPROTO_UDP, syscall.AF_INET)
	assert.NoError(t, err)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)

	killAndWaitCommand(t, cmdServer)
}

func testDisableConnectStatsConfig4(t *testing.T, CLISwitches bool, disableConnect bool, disableStats bool) {
	if runtime.GOARCH != "amd64" && !kernels.MinKernelVersion("5.8.0") {
		t.Skip("Test requires amd64 or kernel >=5.8")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	configYaml := configureDisableSwitchesAndConfig(t, CLISwitches, disableConnect, true, true, disableStats)

	server := getNCCommand(t, "nc.openbsd")
	client := server
	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncSrvChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-unvlp 8084 -s 0.0.0.0"))

	ncCliChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(client)).
		WithArguments(sm.Full("-u 127.0.0.1 8084"))

	execChecker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("serverExec").
			WithProcess(ncSrvChecker).
			WithParent(selfChecker),
		ec.NewProcessExecChecker("clientExec").
			WithProcess(ncCliChecker).
			WithParent(selfChecker),
	)

	connectChecker := ec.NewUnorderedEventChecker(
		ec.NewProcessConnectChecker("serverConnect").
			WithSourceIp(sm.Full("127.0.0.1")).
			WithSourcePort(8084).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithProtocol(tetragon.SocketProtocol_UDP),
	)
	serverStatsChecker := ec.NewUnorderedEventChecker(
		ec.NewProcessSockStatsChecker("serverStats").
			WithSocket(ec.NewSockInfoChecker().
				WithProtocol(tetragon.SocketProtocol_UDP).
				WithSourceIp(sm.Full("127.0.0.1")).
				WithDestinationIp(sm.Full("127.0.0.1")).
				WithSourcePort(8084)),
	)

	obs := enterpriseoth.GetNoConfigObserver(t, ctx, true)
	require.NoError(t, layer3.StartLayer3Progs(ctx, nil))
	if !CLISwitches {
		tp, err := tracingpolicy.FromYAML(configYaml)
		require.NoError(t, err)
		err = observer.GetSensorManager().AddTracingPolicy(ctx, tp)
		require.NoError(t, err)
	}

	option.Config.UsePerfRingBuffer = true
	confmap.UpdateTgRuntimeConf(bpf.MapPrefixPath(), os.Getpid())
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdServer := exec.Command(server, "-unvlp", "8084", "-s", "0.0.0.0")
	stdout, err := cmdServer.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmdServer.Start())
	err = waitForSocketToListen(t, net.ParseIP("0.0.0.0"), 8084, syscall.IPPROTO_UDP, syscall.AF_INET)
	assert.NoError(t, err)

	cmdClient := exec.Command(client, "-u", "127.0.0.1", "8084")
	stdin, err := cmdClient.StdinPipe()
	assert.NoError(t, err)
	assert.NoError(t, cmdClient.Start())
	sendData(t, stdin, "hello")
	waitForData(t, stdout, "hello")

	// Regardless of enabled/disabled network events, we should exepct the exec events
	err = jsonchecker.JsonTestCheck(t, execChecker)
	assert.NoError(t, err)

	connectErr := jsonchecker.JsonTestCheckExpect(t, connectChecker, disableConnect)
	assert.NoError(t, connectErr)

	statsErr := jsonchecker.JsonTestCheckExpect(t, serverStatsChecker, disableStats)
	assert.NoError(t, statsErr)

	killAndWaitCommand(t, cmdServer)
	killAndWaitCommand(t, cmdClient)
}

func TestDisableConnectStats4CLI(t *testing.T) {
	testDisableConnectStatsConfig4(t, true, true, true)
}

func TestNoDisableConnectStats4CLI(t *testing.T) {
	testDisableConnectStatsConfig4(t, true, false, false)
}

func TestDisableConnectStats4NoCLI(t *testing.T) {
	testDisableConnectStatsConfig4(t, false, true, true)
}

func TestNoDisableConnectStats4NoCLI(t *testing.T) {
	testDisableConnectStatsConfig4(t, false, false, false)
}

func (suite *UDPBasic) TestConnectAfterStartEvent4() {
	if runtime.GOARCH != "amd64" && !kernels.MinKernelVersion("5.8.0") {
		suite.T().Skip("Test requires amd64 or kernel >=5.8")
	}

	server := getNCCommand(suite.T(), "nc.openbsd")
	client := server

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncSrvChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-unvlp 8981 -s 0.0.0.0"))

	ncCliChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(client)).
		WithArguments(sm.Full("-u 127.0.0.1 8981"))

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
		ec.NewProcessConnectChecker("serverConnect").
			WithProcess(ncSrvChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithSourcePort(8981).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithProtocol(tetragon.SocketProtocol_UDP),
		// Check client sock stats
		ec.NewProcessSockStatsChecker("clientStats").
			WithProcess(ncCliChecker).
			WithParent(selfChecker).
			WithSocket(ec.NewSockInfoChecker().
				WithProtocol(tetragon.SocketProtocol_UDP).
				WithDestinationIp(sm.Full("127.0.0.1")).
				WithDestinationPort(8981)).
			WithStats(ec.NewSocketStatsChecker().
				WithBytesSent(5).
				WithSegsOut(1)),
		// Check server sock stats
		ec.NewProcessSockStatsChecker("serverStats").
			WithProcess(ncSrvChecker).
			WithParent(selfChecker).
			WithSocket(ec.NewSockInfoChecker().
				WithProtocol(tetragon.SocketProtocol_UDP).
				WithSourceIp(sm.Full("127.0.0.1")).
				WithDestinationIp(sm.Full("127.0.0.1")).
				WithSourcePort(8981)).
			WithStats(ec.NewSocketStatsChecker().
				WithBytesReceived(5).
				WithSegsIn(1)),
	)

	suite.readyWG.Wait()
	cmdClient := exec.Command(client, "-u", "127.0.0.1", "8981")
	stdin, err := cmdClient.StdinPipe()
	suite.Assert().NoError(err)
	suite.Assert().NoError(cmdClient.Start())
	sendData(suite.T(), stdin, "hello")
	waitForData(suite.T(), stdoutUDP8981, "hello")

	err = jsonchecker.JsonTestCheck(suite.T(), checker)
	suite.Assert().NoError(err)

	killAndWaitCommand(suite.T(), cmdClient)
}

func (suite *UDPBasic) TestUdpMulticast4() {
	if runtime.GOARCH != "amd64" && !kernels.MinKernelVersion("5.8.0") {
		suite.T().Skip("Test requires amd64 or kernel >=5.8")
	}

	server := getSocatCommand(suite.T(), "socat")
	client := server

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	socatSrvChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("- UDP4-LISTEN:8100,ip-add-membership=224.0.0.1:lo"))

	socatCliChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(client)).
		WithArguments(sm.Full("- UDP4-DATAGRAM:224.0.0.1:8100"))

	clientStatsChecker := ec.NewProcessSockStatsChecker("clientStats1").
		WithProcess(socatCliChecker).
		WithParent(selfChecker).
		WithSocket(ec.NewSockInfoChecker().
			WithProtocol(tetragon.SocketProtocol_UDP).
			WithDestinationIp(sm.Full("224.0.0.1")).
			WithDestinationPort(8100)).
		WithStats(ec.NewSocketStatsChecker().
			WithBytesSent(5).
			WithBytesReceived(0))

	serverStatsChecker := ec.NewProcessSockStatsChecker("serverStats").
		WithProcess(socatSrvChecker).
		WithParent(selfChecker).
		WithSocket(ec.NewSockInfoChecker().
			WithProtocol(tetragon.SocketProtocol_UDP).
			WithSourcePort(8100)).
		WithStats(ec.NewSocketStatsChecker().
			WithBytesReceived(5).
			WithBytesSent(0))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("serverExec").
			WithProcess(socatSrvChecker).
			WithParent(selfChecker),
		ec.NewProcessExecChecker("clientExec").
			WithProcess(socatCliChecker).
			WithParent(selfChecker),
		ec.NewProcessConnectChecker("serverConnect").
			WithProcess(socatSrvChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("224.0.0.1")).
			WithSourcePort(8100).
			WithProtocol(tetragon.SocketProtocol_UDP),
		ec.NewProcessConnectChecker("clientConnect").
			WithProcess(socatCliChecker).
			WithParent(selfChecker).
			WithDestinationIp(sm.Full("224.0.0.1")).
			WithDestinationPort(8100).
			WithProtocol(tetragon.SocketProtocol_UDP),
		clientStatsChecker,
		serverStatsChecker,
	)

	suite.readyWG.Wait()
	cmdServer := exec.Command(server, "-", "UDP4-LISTEN:8100,ip-add-membership=224.0.0.1:lo")
	suite.Assert().NoError(cmdServer.Start())
	err := waitForSocketToListen(suite.T(), net.ParseIP("0.0.0.0"), 8100, syscall.IPPROTO_UDP, syscall.AF_INET)
	suite.Assert().NoError(err)

	cmdClient := exec.Command(client, "-", "UDP4-DATAGRAM:224.0.0.1:8100")
	stdinClient, err := cmdClient.StdinPipe()
	suite.Assert().NoError(err)
	suite.Assert().NoError(cmdClient.Start())
	sendData(suite.T(), stdinClient, "hello")

	err = jsonchecker.JsonTestCheck(suite.T(), checker)
	suite.Assert().NoError(err)

	killAndWaitCommand(suite.T(), cmdServer)
	killAndWaitCommand(suite.T(), cmdClient)
}

func (suite *UDPBasic) TestUdpConnectEvent6() {
	if runtime.GOARCH != "amd64" && !kernels.MinKernelVersion("5.8.0") {
		suite.T().Skip("Test requires amd64 or kernel >=5.8")
	}

	server := getNCCommand(suite.T(), "nc.openbsd")
	client := server

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncSrvChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-6unvlp 8081 -s ::"))

	ncCliChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(client)).
		WithArguments(sm.Full("-6u ::1 8081"))

	clientStatsChecker := ec.NewProcessSockStatsChecker("clientStats").
		WithProcess(ncCliChecker).
		WithParent(selfChecker).
		WithSocket(ec.NewSockInfoChecker().
			WithProtocol(tetragon.SocketProtocol_UDP).
			WithDestinationIp(sm.Full("::1")).
			WithDestinationPort(8081))

	serverStatsChecker := ec.NewProcessSockStatsChecker("serverStats").
		WithProcess(ncSrvChecker).
		WithParent(selfChecker).
		WithSocket(ec.NewSockInfoChecker().
			WithProtocol(tetragon.SocketProtocol_UDP).
			WithSourceIp(sm.Full("::1")).
			WithDestinationIp(sm.Full("::1")).
			WithSourcePort(8081))

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
		ec.NewProcessConnectChecker("serverConnect").
			WithProcess(ncSrvChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("::1")).
			WithSourcePort(8081).
			WithDestinationIp(sm.Full("::1")).
			WithProtocol(tetragon.SocketProtocol_UDP),
		ec.NewProcessCloseChecker("serverClose").
			WithProcess(ncSrvChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("::1")).
			WithSourcePort(8081).
			WithDestinationIp(sm.Full("::1")).
			WithProtocol(tetragon.SocketProtocol_UDP),
		ec.NewProcessCloseChecker("clientClose").
			WithProcess(ncCliChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("::1")).
			WithDestinationPort(8081).
			WithDestinationIp(sm.Full("::1")).
			WithProtocol(tetragon.SocketProtocol_UDP),
		clientStatsChecker,
		serverStatsChecker,
	)

	// We need to check sockstats using a custom stateful checker since stats events can
	// be split up and so checking the individual events won't work. We need to instead
	// keep a cumulative count of the stats we have seen and compare them to expected
	// totals.
	var clientBytesSent uint64
	var clientSegsOut uint32
	var serverBytesReceived uint64
	var serverSegsIn uint32
	statsChecker := &ec.FnEventChecker{
		NextCheckFn: func(event_ ec.Event, _ *slog.Logger) (bool, error) {
			event, ok := event_.(*tetragon.ProcessSockStats)
			if !ok {
				return false, fmt.Errorf("event is not a sockstats event")
			}

			if event.Stats == nil {
				return false, fmt.Errorf("event has no stats field")
			}

			if clientStatsChecker.Check(event) == nil {
				clientBytesSent += event.Stats.BytesSent
				clientSegsOut += event.Stats.SegsOut
				return false, nil
			}

			if serverStatsChecker.Check(event) == nil {
				serverBytesReceived += event.Stats.BytesReceived
				serverSegsIn += event.Stats.SegsIn
				return false, nil
			}

			return false, fmt.Errorf("sockstats event is neither from client nor server")
		},
		FinalCheckFn: func(_ *slog.Logger) error {
			defer func() {
				clientBytesSent = 0
				clientSegsOut = 0
				serverBytesReceived = 0
				serverSegsIn = 0
			}()

			if clientBytesSent != 5 {
				return fmt.Errorf("Unexecpected clientBytesSent, wanted 5, got %d", clientBytesSent)
			}

			if clientSegsOut != 1 {
				return fmt.Errorf("Unexecpected clientSegsOut, wanted 1, got %d", clientSegsOut)
			}

			if serverBytesReceived != 5 {
				return fmt.Errorf("Unexecpected serverBytesReceived, wanted 5, got %d", serverBytesReceived)
			}

			if serverSegsIn != 1 {
				return fmt.Errorf("Unexecpected serverSegsIn, wanted 1, got %d", serverSegsIn)
			}

			return nil
		},
	}

	suite.readyWG.Wait()
	cmdServer := exec.Command(server, "-6unvlp", "8081", "-s", "::")
	stdout, err := cmdServer.StdoutPipe()
	suite.Assert().NoError(err)
	suite.Assert().NoError(cmdServer.Start())
	err = waitForSocketToListen(suite.T(), net.ParseIP("::"), 8081, syscall.IPPROTO_UDP, syscall.AF_INET6)
	suite.Assert().NoError(err)

	cmdClient := exec.Command(client, "-6u", "::1", "8081")
	stdin, err := cmdClient.StdinPipe()
	suite.Assert().NoError(err)
	suite.Assert().NoError(cmdClient.Start())
	sendData(suite.T(), stdin, "hello")

	waitForData(suite.T(), stdout, "hello")

	killAndWaitCommand(suite.T(), cmdServer)
	killAndWaitCommand(suite.T(), cmdClient)

	err = jsonchecker.JsonTestCheck(suite.T(), checker)
	suite.Assert().NoError(err)

	err = jsonchecker.JsonTestCheck(suite.T(), statsChecker)
	suite.Assert().NoError(err)
}

func (suite *UDPBasic) TestListenEvent6() {
	if runtime.GOARCH != "amd64" && !kernels.MinKernelVersion("5.8.0") {
		suite.T().Skip("Test requires amd64 or kernel >=5.8")
	}

	server := getNCCommand(suite.T(), "nc.openbsd")

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncSrvChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-6unvlp 8082 -s ::"))

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
			WithPort(8082).
			WithProtocol(tetragon.SocketProtocol_UDP),
	)

	suite.readyWG.Wait()
	cmdServer := exec.Command(server, "-6unvlp", "8082", "-s", "::")
	suite.Assert().NoError(cmdServer.Start())
	err := waitForSocketToListen(suite.T(), net.ParseIP("::"), 8082, syscall.IPPROTO_UDP, syscall.AF_INET6)
	suite.Assert().NoError(err)

	err = jsonchecker.JsonTestCheck(suite.T(), checker)
	suite.Assert().NoError(err)

	killAndWaitCommand(suite.T(), cmdServer)
}

func (suite *UDPBasic) TestConnectAfterStartEvent6() {
	if runtime.GOARCH != "amd64" && !kernels.MinKernelVersion("5.8.0") {
		suite.T().Skip("Test requires amd64 or kernel >=5.8")
	}

	server := getNCCommand(suite.T(), "nc.openbsd")
	client := server

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncSrvChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-6unvlp 8981 -s ::"))

	ncCliChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(client)).
		WithArguments(sm.Full("-6u ::1 8981"))

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
		ec.NewProcessConnectChecker("serverConnect").
			WithProcess(ncSrvChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("::1")).
			WithSourcePort(8981).
			WithDestinationIp(sm.Full("::1")).
			WithProtocol(tetragon.SocketProtocol_UDP),
		// Check client sock stats
		ec.NewProcessSockStatsChecker("clientConnect").
			WithProcess(ncCliChecker).
			WithParent(selfChecker).
			WithSocket(ec.NewSockInfoChecker().
				WithProtocol(tetragon.SocketProtocol_UDP).
				WithDestinationIp(sm.Full("::1")).
				WithDestinationPort(8981)).
			WithStats(ec.NewSocketStatsChecker().
				WithBytesSent(5).
				WithSegsOut(1)),
		// Check server sock stats
		ec.NewProcessSockStatsChecker("clientStats").
			WithProcess(ncSrvChecker).
			WithParent(selfChecker).
			WithSocket(ec.NewSockInfoChecker().
				WithProtocol(tetragon.SocketProtocol_UDP).
				WithSourceIp(sm.Full("::1")).
				WithDestinationIp(sm.Full("::1")).
				WithSourcePort(8981)).
			WithStats(ec.NewSocketStatsChecker().
				WithBytesReceived(5).
				WithSegsIn(1)),
	)

	suite.readyWG.Wait()
	cmdClient := exec.Command(client, "-6u", "::1", "8981")
	stdin, err := cmdClient.StdinPipe()
	suite.Assert().NoError(err)
	suite.Assert().NoError(cmdClient.Start())
	sendData(suite.T(), stdin, "hello")
	waitForData(suite.T(), stdoutUDP8981V6, "hello")

	err = jsonchecker.JsonTestCheck(suite.T(), checker)
	suite.Assert().NoError(err)

	killAndWaitCommand(suite.T(), cmdClient)
}

func testDnsEvents(t *testing.T, CLISwitches, withQuestions bool) {
	if !utils.CGroupSKBAvailable() {
		t.Skipf("This test requires CGroup/SKB, skipping")
	}

	if runtime.GOARCH != "amd64" && !kernels.MinKernelVersion("5.8.0") {
		t.Skip("Test requires amd64 or kernel >=5.8")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	if CLISwitches {
		switches := []cli.SwitchSettings{
			{KeyPtr: &enterpriseOption.Config.Layer3CLIEnable, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableNetworkEvents, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableUDP, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableUDPCGroup, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableUserDNS, Value: true},
			{KeyPtr: &enterpriseOption.Config.DNSPorts, Value: []int{53}},
		}
		if withQuestions {
			switches = append(switches, cli.SwitchSettings{KeyPtr: &enterpriseOption.Config.DNSReportQuestions, Value: true})
		}
		require.NoError(t, cli.SetSwitches(t, switches))
	}

	obs := enterpriseoth.GetNoConfigObserver(t, ctx, true)
	require.NoError(t, layer3.StartLayer3Progs(ctx, nil))

	if !CLISwitches {
		config := udpConfigWithoutDnsQuestions
		if withQuestions {
			config = udpConfigWithDnsQuestions
		}
		tp, err := tracingpolicy.FromYAML(config)
		require.NoError(t, err)
		err = observer.GetSensorManager().AddTracingPolicy(ctx, tp)
		require.NoError(t, err)
	}

	option.Config.UsePerfRingBuffer = true
	confmap.UpdateTgRuntimeConf(bpf.MapPrefixPath(), os.Getpid())
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	curl4Checker := ec.NewProcessChecker().
		WithBinary(sm.Suffix("curl")).
		WithArguments(sm.Full("-4 https://www.google.com"))

	curl6Checker := ec.NewProcessChecker().
		WithBinary(sm.Suffix("curl")).
		WithArguments(sm.Full("-6 https://www.google.com"))

	checks := []ec.EventChecker{
		ec.NewProcessExecChecker("curl4Exec").
			WithProcess(curl4Checker).
			WithParent(selfChecker),
		ec.NewProcessConnectChecker("curl4Connect").
			WithProcess(curl4Checker).
			WithParent(selfChecker).
			WithDestinationPort(53).
			WithProtocol(tetragon.SocketProtocol_UDP),
		ec.NewProcessDnsChecker("curl4DnsReply").
			WithProcess(curl4Checker).
			WithParent(selfChecker).
			WithDns(ec.NewDnsInfoChecker().
				WithRcode(0).
				WithNames(ec.NewStringListMatcher().WithValues(sm.Full("www.google.com."))).
				// TODO: remove this check at some point once we stop populating
				// Dns.QuestionTypes
				WithQuestionTypes(ec.NewUint32ListMatcher().WithValues(1)).
				WithQueryTypes(ec.NewDnsTypeListMatcher().WithValues(ec.NewDnsTypeChecker(tetragon.DnsType_A))).
				// TODO: remove this check at some point once we stop populating
				// Dns.AnswerTypes
				WithAnswerTypes(ec.NewUint32ListMatcher().WithValues(1)).
				WithResponseTypes(ec.NewDnsTypeListMatcher().WithValues(ec.NewDnsTypeChecker(tetragon.DnsType_A))).
				WithIps(ec.NewStringListMatcher().
					WithOperator(listmatcher.Subset).
					// Match a valid IPv4 address
					WithValues(sm.Regex(`^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$`)))),
		ec.NewProcessExecChecker("curl6Exec").
			WithProcess(curl6Checker).
			WithParent(selfChecker),
		ec.NewProcessConnectChecker("curl6Connect").
			WithProcess(curl6Checker).
			WithParent(selfChecker).
			WithDestinationPort(53).
			WithProtocol(tetragon.SocketProtocol_UDP),
		ec.NewProcessDnsChecker("curl6DnsReply").
			WithProcess(curl6Checker).
			WithParent(selfChecker).
			WithDns(ec.NewDnsInfoChecker().
				WithRcode(0).
				WithNames(ec.NewStringListMatcher().WithValues(sm.Full("www.google.com."))).
				// TODO: remove this check at some point once we stop populating
				// Dns.QuestionTypes
				WithQuestionTypes(ec.NewUint32ListMatcher().WithValues(28)).
				WithQueryTypes(ec.NewDnsTypeListMatcher().WithValues(ec.NewDnsTypeChecker(tetragon.DnsType_AAAA))).
				// TODO: remove this check at some point once we stop populating
				// Dns.AnswerTypes
				WithAnswerTypes(ec.NewUint32ListMatcher().WithValues(28)).
				WithResponseTypes(ec.NewDnsTypeListMatcher().WithValues(ec.NewDnsTypeChecker(tetragon.DnsType_AAAA))).
				WithIps(ec.NewStringListMatcher().
					WithOperator(listmatcher.Subset).
					// Full IPv6 regex is probably too complicated, let's just see if it
					// contains a ::
					WithValues(sm.Contains(`::`)))),
	}

	questionChecks := []ec.EventChecker{
		// This is less specific than the reply above so it must be specified second
		ec.NewProcessDnsChecker("curl4DnsRequest").
			WithProcess(curl4Checker).
			WithParent(selfChecker).
			WithDns(ec.NewDnsInfoChecker().
				WithRcode(0).
				WithNames(ec.NewStringListMatcher().WithValues(sm.Full("www.google.com."))).
				// TODO: remove this check at some point once we stop populating
				// Dns.QuestionTypes
				WithQuestionTypes(ec.NewUint32ListMatcher().WithValues(1)).
				WithQueryTypes(ec.NewDnsTypeListMatcher().WithValues(ec.NewDnsTypeChecker(tetragon.DnsType_A)))),
		// This is less specific than the reply above so it must be specified second
		ec.NewProcessDnsChecker("curl6DnsRequest").
			WithProcess(curl6Checker).
			WithParent(selfChecker).
			WithDns(ec.NewDnsInfoChecker().
				WithRcode(0).
				WithNames(ec.NewStringListMatcher().WithValues(sm.Full("www.google.com."))).
				WithQueryTypes(ec.NewDnsTypeListMatcher().WithValues(ec.NewDnsTypeChecker(tetragon.DnsType_AAAA)))),
	}

	if withQuestions {
		checks = append(checks, questionChecks...)
	}

	checker := ec.NewUnorderedEventChecker(checks...)

	curl4 := exec.Command("curl", "-4", "https://www.google.com")
	assert.NoError(t, curl4.Start())

	curl6 := exec.Command("curl", "-6", "https://www.google.com")
	assert.NoError(t, curl6.Start())

	// Adjust JSON checker delay to account for events that might be coming in more
	// slowly in 5.4 kernels
	oldDelay := jsonchecker.RetryDelay
	jsonchecker.RetryDelay = oldDelay * 2
	err := jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
	jsonchecker.RetryDelay = oldDelay
}

func TestDnsEventsWithQuestions(t *testing.T) {
	t.Skip("Disabled due to flakiness")
	testDnsEvents(t, false, true)
}

func TestDnsEventsWithoutQuestions(t *testing.T) {
	enterprisepolicytest.DoObserverTest(t, "layer3-dns-curl", nil)
}

func TestDnsEventsWithQuestionsCLI(t *testing.T) {
	t.Skip("Disabled due to flakiness")
	testDnsEvents(t, true, true)
}

func TestDnsEventsWithoutQuestionsCLI(t *testing.T) {
	enterprisepolicytest.DoObserverTest(t, "layer3-dns-curl-no-policy", nil)
}

func testDisableCloseConfig(t *testing.T, CLISwitches, disableClose bool) {
	if runtime.GOARCH != "amd64" && !kernels.MinKernelVersion("5.8.0") {
		t.Skip("Test requires amd64 or kernel >=5.8")
	}

	bpf.CheckOrMountCgroup2()

	server := getNCCommand(t, "nc.openbsd")
	client := server

	serverProcess := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-unvlp 8081 -s 0.0.0.0"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessCloseChecker("serverClose").
			WithProcess(serverProcess),
	)

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	if CLISwitches {
		require.NoError(t, cli.SetSwitches(t, []cli.SwitchSettings{
			{KeyPtr: &enterpriseOption.Config.Layer3CLIEnable, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableNetworkEvents, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableUDP, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableUDPCGroup, Value: utils.CGroupSKBAvailable()},
			{KeyPtr: &enterpriseOption.Config.UDPStatsInterval, Value: 20 * time.Second},
			{KeyPtr: &enterpriseOption.Config.UDPDisableCloseEvents, Value: disableClose},
		}))
	}

	obs := enterpriseoth.GetNoConfigObserver(t, ctx, true)
	require.NoError(t, layer3.StartLayer3Progs(ctx, nil))

	if !CLISwitches {
		disableCloseConfig := udpConfigDisableClose + strconv.FormatBool(disableClose)
		tp, err := tracingpolicy.FromYAML(disableCloseConfig)
		require.NoError(t, err)
		err = observer.GetSensorManager().AddTracingPolicy(ctx, tp)
		require.NoError(t, err)
	}
	option.Config.UsePerfRingBuffer = true
	confmap.UpdateTgRuntimeConf(bpf.MapPrefixPath(), os.Getpid())
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	cmdServer := exec.Command(server, "-unvlp", "8081", "-s", "0.0.0.0")
	stdout, err := cmdServer.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmdServer.Start())
	err = waitForSocketToListen(t, net.IPv4(0, 0, 0, 0), 8081, syscall.IPPROTO_UDP, syscall.AF_INET)
	require.NoError(t, err)

	cmdClient := exec.Command(client, "-u", "127.0.0.1", "8081")
	stdin, err := cmdClient.StdinPipe()
	require.NoError(t, err)
	require.NoError(t, cmdClient.Start())
	sendData(t, stdin, "hello")
	waitForData(t, stdout, "hello")

	killAndWaitCommand(t, cmdServer)

	err = jsonchecker.JsonTestCheckExpect(t, checker, disableClose)
	require.NoError(t, err)

	killAndWaitCommand(t, cmdClient)
}

func TestDisableClose(t *testing.T) {
	testDisableCloseConfig(t, false, true)
}

func TestNoDisableClose(t *testing.T) {
	testDisableCloseConfig(t, false, false)
}

func TestDisableCloseCLI(t *testing.T) {
	testDisableCloseConfig(t, true, true)
}

func TestNoDisableCloseCLI(t *testing.T) {
	testDisableCloseConfig(t, true, false)
}

func testDisableListenConfig(t *testing.T, CLISwitches, disableListen bool) {
	if runtime.GOARCH != "amd64" && !kernels.MinKernelVersion("5.8.0") {
		t.Skip("Test requires amd64 or kernel >=5.8")
	}

	//bpf.CheckOrMountCgroup2()

	server := getNCCommand(t, "nc.openbsd")

	serverProcess := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-unvlp 8081 -s 0.0.0.0"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessListenChecker("serverListen").
			WithProcess(serverProcess),
	)

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	if CLISwitches {
		require.NoError(t, cli.SetSwitches(t, []cli.SwitchSettings{
			{KeyPtr: &enterpriseOption.Config.Layer3CLIEnable, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableNetworkEvents, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableUDP, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableUDPCGroup, Value: utils.CGroupSKBAvailable()},
			{KeyPtr: &enterpriseOption.Config.UDPStatsInterval, Value: 20 * time.Second},
			{KeyPtr: &enterpriseOption.Config.UDPDisableListenEvents, Value: disableListen},
		}))
	}

	obs := enterpriseoth.GetNoConfigObserver(t, ctx, true)
	require.NoError(t, layer3.StartLayer3Progs(ctx, nil))

	if !CLISwitches {
		disableListenConfig := udpConfigDisableListen + strconv.FormatBool(disableListen)
		tp, err := tracingpolicy.FromYAML(disableListenConfig)
		require.NoError(t, err)
		err = observer.GetSensorManager().AddTracingPolicy(ctx, tp)
		require.NoError(t, err)
	}
	option.Config.UsePerfRingBuffer = true
	confmap.UpdateTgRuntimeConf(bpf.MapPrefixPath(), os.Getpid())
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	cmdServer := exec.Command(server, "-unvlp", "8081", "-s", "0.0.0.0")
	require.NoError(t, cmdServer.Start())
	err := waitForSocketToListen(t, net.IPv4(0, 0, 0, 0), 8081, syscall.IPPROTO_UDP, syscall.AF_INET)
	require.NoError(t, err)

	err = jsonchecker.JsonTestCheckExpect(t, checker, disableListen)

	killAndWaitCommand(t, cmdServer)

	require.NoError(t, err)
}

func TestDisableListen(t *testing.T) {
	testDisableListenConfig(t, false, true)
}

func TestNoDisableListen(t *testing.T) {
	testDisableListenConfig(t, false, false)
}

func TestNoDisableListenCLI(t *testing.T) {
	testDisableListenConfig(t, true, false)
}

func TestDisableListenCLI(t *testing.T) {
	testDisableListenConfig(t, true, true)
}

func udpGcMetricGet(ty socketmetrics.UDPGCType) float64 {
	// ToFloat64 is computationally expensive so only use for testing
	counter := socketmetrics.SocketStatsUDPGC.WithLabelValues(socketmetrics.UDPGCTypeStrings[ty])
	return testutil.ToFloat64(counter)
}

func testGC(t *testing.T, CLISwitches, defaultInterval bool, interval int, numExpectedGCRuns int) {
	t.Skip("Disabled due to unstable timing on CI runners.")
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	server := getNCCommand(t, "nc.openbsd")
	client := server

	var err error
	if CLISwitches {
		switches := []cli.SwitchSettings{
			{KeyPtr: &enterpriseOption.Config.Layer3CLIEnable, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableNetworkEvents, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableUDP, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableUDPCGroup, Value: utils.CGroupSKBAvailable()},
		}
		if !defaultInterval {
			switches = append(switches, cli.SwitchSettings{KeyPtr: &enterpriseOption.Config.UDPStatsInterval, Value: time.Duration(interval) * time.Second})
		}
		cli.SetSwitches(t, switches)
	}

	obs := enterpriseoth.GetNoConfigObserver(t, ctx, true)
	require.NoError(t, layer3.StartLayer3Progs(ctx, nil))

	if !CLISwitches {
		GCTestConfig := udpConfigBasic
		if !defaultInterval {
			GCTestConfig += "\n      statsInterval: " + strconv.Itoa(interval)
		}
		tp, err := tracingpolicy.FromYAML(GCTestConfig)
		require.NoError(t, err)
		err = observer.GetSensorManager().AddTracingPolicy(ctx, tp)
		require.NoError(t, err)
	}

	option.Config.UsePerfRingBuffer = true
	confmap.UpdateTgRuntimeConf(bpf.MapPrefixPath(), os.Getpid())
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdServer := exec.Command(server, "-unvlp", "8086", "-s", "0.0.0.0")
	stdout, err := cmdServer.StdoutPipe()
	assert.NoError(t, err)
	assert.NoError(t, cmdServer.Start())
	err = waitForSocketToListen(t, net.ParseIP("0.0.0.0"), 8086, syscall.IPPROTO_UDP, syscall.AF_INET)
	assert.NoError(t, err)

	cmdClient := exec.Command(client, "-u", "127.0.0.1", "8086")
	stdin, err := cmdClient.StdinPipe()
	assert.NoError(t, err)
	assert.NoError(t, cmdClient.Start())
	sendData(t, stdin, "hello")
	waitForData(t, stdout, "hello")

	GCTickerStart := udpGcMetricGet(socketmetrics.UDPGCTypeTicker)

	defaultGCInterval := 60
	var timeToRun int
	if defaultInterval {
		timeToRun = defaultGCInterval * numExpectedGCRuns
	} else {
		timeToRun = interval * numExpectedGCRuns
	}

	time.Sleep(time.Duration(timeToRun) * time.Second)

	GCTickerEnd := udpGcMetricGet(socketmetrics.UDPGCTypeTicker)
	numActualGCRuns := int(GCTickerEnd - GCTickerStart)

	// Allow +- 1 error to prevent flakes
	assert.InDelta(t, numExpectedGCRuns, numActualGCRuns, 1.0,
		"Expected number of runs: %d, actual number: %d",
		numExpectedGCRuns, numActualGCRuns)

	killAndWaitCommand(t, cmdServer)
	killAndWaitCommand(t, cmdClient)
}

func TestGCDefaultInterval(t *testing.T) {
	testGC(t, false, true, 60, 2)
}

func TestGCWithNonzeroInterval(t *testing.T) {
	testGC(t, false, false, 5, 4)
}

func TestGCDefaultIntervalCLI(t *testing.T) {
	testGC(t, true, true, 60, 2)
}

func TestGCWithNonzeroIntervalCLI(t *testing.T) {
	testGC(t, true, false, 5, 4)
}

// FIXME: net io_uring test seems to time out on ARM.
func (suite *UDPBasic) TestUdpIOUringConnectEvent() {
	if !utils.CGroupSKBAvailable() {
		suite.T().Skipf("This test requires CGroup/SKB, skipping")
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "x86_64" {
		suite.T().Skipf("Test seems to time out on ARM")
	}
	if !testutils.NetIOUringAvailable() {
		suite.T().Skipf("Net io_uring not available, skipping")
	}

	server := testutils.RepoRootPath("contrib/tester-progs/io_uring/udp_iouring_server")
	client := getNCCommand(suite.T(), "nc.openbsd")

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncSrvChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server))

	ncCliChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(client)).
		WithArguments(sm.Full("-u 127.0.0.1 8000"))

	clientStatsChecker := ec.NewProcessSockStatsChecker("clientStats").
		WithProcess(ncCliChecker).
		WithParent(selfChecker).
		WithSocket(ec.NewSockInfoChecker().
			WithProtocol(tetragon.SocketProtocol_UDP).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithDestinationPort(8000))

	serverStatsChecker := ec.NewProcessSockStatsChecker("serverStats").
		WithProcess(ncSrvChecker).
		WithParent(selfChecker).
		WithSocket(ec.NewSockInfoChecker().
			WithProtocol(tetragon.SocketProtocol_UDP).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithSourcePort(8000))

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
		ec.NewProcessConnectChecker("serverConnect").
			WithProcess(ncSrvChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithSourcePort(8000).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithProtocol(tetragon.SocketProtocol_UDP),
		clientStatsChecker,
		serverStatsChecker,
	)

	// We need to check sockstats using a custom stateful checker since stats events can
	// be split up and so checking the individual events won't work. We need to instead
	// keep a cumulative count of the stats we have seen and compare them to expected
	// totals.
	var clientBytesSent uint64
	var clientBytesReceived uint64
	var clientSegsOut uint32
	var clientSegsIn uint32
	var serverBytesSent uint64
	var serverBytesReceived uint64
	var serverSegsOut uint32
	var serverSegsIn uint32

	statsChecker := &ec.FnEventChecker{
		NextCheckFn: func(event_ ec.Event, _ *slog.Logger) (bool, error) {
			event, ok := event_.(*tetragon.ProcessSockStats)
			if !ok {
				return false, fmt.Errorf("event is not a sockstats event")
			}

			if event.Stats == nil {
				return false, fmt.Errorf("event has no stats field")
			}

			if clientStatsChecker.Check(event) == nil {
				clientBytesSent += event.Stats.BytesSent
				clientBytesReceived += event.Stats.BytesReceived
				clientSegsIn += event.Stats.SegsIn
				clientSegsOut += event.Stats.SegsOut
				return false, nil
			}

			if serverStatsChecker.Check(event) == nil {
				serverBytesSent += event.Stats.BytesSent
				serverBytesReceived += event.Stats.BytesReceived
				serverSegsIn += event.Stats.SegsIn
				serverSegsOut += event.Stats.SegsOut
				return false, nil
			}

			return false, fmt.Errorf("sockstats event is neither from client nor server")
		},
		FinalCheckFn: func(_ *slog.Logger) error {
			defer func() {
				clientBytesSent = 0
				clientBytesReceived = 0
				clientSegsIn = 0
				clientSegsOut = 0
				serverBytesSent = 0
				serverBytesReceived = 0
				serverSegsIn = 0
				serverSegsOut = 0
			}()

			if clientBytesSent != 5 {
				return fmt.Errorf("Unexecpected clientBytesSent, wanted 5, got %d", clientBytesSent)
			}

			if clientBytesReceived != 5 {
				return fmt.Errorf("Unexecpected clientBytesReceived, wanted 5, got %d", clientBytesReceived)
			}

			if clientSegsIn != 1 {
				return fmt.Errorf("Unexecpected clientSegsIn, wanted 1, got %d", clientSegsIn)
			}

			if clientSegsOut != 1 {
				return fmt.Errorf("Unexecpected clientSegsOut, wanted 1, got %d", clientSegsOut)
			}

			if serverBytesSent != 5 {
				return fmt.Errorf("Unexecpected serverBytesSent, wanted 5, got %d", serverBytesSent)
			}

			if serverBytesReceived != 5 {
				return fmt.Errorf("Unexecpected serverBytesReceived, wanted 5, got %d", serverBytesReceived)
			}

			if serverSegsIn != 1 {
				return fmt.Errorf("Unexecpected serverSegsIn, wanted 1, got %d", serverSegsIn)
			}

			if serverSegsOut != 1 {
				return fmt.Errorf("Unexecpected serverSegsOut, wanted 1, got %d", serverSegsOut)
			}

			return nil
		},
	}

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
			suite.T().Fatal("received empty line from UDP server")
		}
		if strings.HasPrefix(string(line), "NotReady") {
			suite.T().Fatalf("UDP server failed to start: '%s'", string(line))
		}
	}

	serverPid := uint32(cmdServer.Process.Pid)
	logger.GetLogger().Info("Running", "ServerPid", serverPid)

	cmdClient := exec.Command(client, "-u", "127.0.0.1", "8000")
	stdin, err := cmdClient.StdinPipe()
	suite.Assert().NoError(err)
	suite.Assert().NoError(cmdClient.Start())
	sendData(suite.T(), stdin, "hello")
	err = jsonchecker.JsonTestCheck(suite.T(), checker)
	suite.Assert().NoError(err)

	err = jsonchecker.JsonTestCheck(suite.T(), statsChecker)
	suite.Assert().NoError(err)

	killAndWaitCommand(suite.T(), cmdServer)
	killAndWaitCommand(suite.T(), cmdClient)
}
