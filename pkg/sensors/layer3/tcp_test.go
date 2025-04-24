//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package layer3_test

import (
	"bufio"
	"context"
	"fmt"
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
	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper/docker"
	"github.com/cilium/tetragon/pkg/reader/namespace"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/jsonchecker"
	enterpriseoth "github.com/isovalent/hubble-fgs/pkg/observer/observertesthelper"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3"
	"github.com/isovalent/hubble-fgs/pkg/sensors/networkWatermarksEvents"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
	"github.com/isovalent/hubble-fgs/pkg/testutils"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"

	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
)

const tcpConfigLegacy = `
apiversion: cilium.io/v1alpha1
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

// Note 20.0.0.0/8 is the DoD and isn't routable on the Internet
// This is included to test TCP latency timestamps are NOT added
// to any real TCP packets.
const tcpConfig = `
apiversion: cilium.io/v1alpha1
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
      latency:
        enable: true
        matchSubnets: [20.0.0.0/8]
        min: 0
        max: 10000
    networkWatermarksExitGen:
      enable: true
      interval: 1000
    dns:
      enable: true
`

const tcpBasicConfig = `
apiversion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tcp"
spec:
  parser:
    tcp:
      enable: true
`

const tcpBasicConfigWOEnable = `
apiversion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tcp"
spec:
  parser:
    tcp:
`

// Setting TCP RTT max to 1,000,000 means 1% equates to
// 10ms, which a packet across loopback should easily be
// quicker than.
const tcpBasicConfigWithRTTDetection = `
apiversion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tcp"
spec:
  parser:
    tcp:
      enable: true
      histogram:
        enable: true
        min: 0
        max: 1000000
`

// Setting TCP latency max to 1,000,000 means 1% equates to
// 10ms, which a packet across loopback should easily be
// quicker than.
const tcpBasicConfigWithLatencyDetection = `
apiversion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tcp"
spec:
  parser:
    tcp:
      enable: true
      latency:
        enable: true
        matchSubnets: [127.0.0.1/32]
        matchPorts: [8082]
        min: 0
        max: 1000000
`

// NB(kkourt): Function(t *testing.T, ctx context.Context) is the reasonable
// thing to do here even if revive complains.
//
//revive:disable:context-as-argument
func getBasicTcpObserver(t *testing.T, ctx context.Context, docker bool) *observer.Observer {
	return getLayer3Observer(t, ctx, tcpBasicConfig, !docker)
}

func getTcpObserverWithRTTDetection(t *testing.T, ctx context.Context, docker bool) *observer.Observer {
	return getLayer3Observer(t, ctx, tcpBasicConfigWithRTTDetection, !docker)
}

func getTcpObserverWithLatencyDetection(t *testing.T, ctx context.Context, docker bool) *observer.Observer {
	return getLayer3Observer(t, ctx, tcpBasicConfigWithLatencyDetection, !docker)
}

func getTcpObserverDisableEvents(t *testing.T, ctx context.Context, docker bool, CLISwitches bool, disableConnect bool, disableClose bool, disableAccept bool, disableListen bool) *observer.Observer {
	eventDisableConfig := `
      disableEvents:
`
	eventDisableConfig += "\n        disableConnect: " + strconv.FormatBool(disableConnect)
	eventDisableConfig += "\n        disableClose: " + strconv.FormatBool(disableClose)
	eventDisableConfig += "\n        disableAccept: " + strconv.FormatBool(disableAccept)
	eventDisableConfig += "\n        disableListen: " + strconv.FormatBool(disableListen)

	var tcpDisableEventsConfig string
	if CLISwitches {
		tcpDisableEventsConfig = tcpBasicConfigWOEnable + eventDisableConfig
	} else {
		tcpDisableEventsConfig = tcpBasicConfig + eventDisableConfig
	}
	return getLayer3Observer(t, ctx, tcpDisableEventsConfig, !docker)
}

func TestConnectEvent4(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	curlChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix("curl")).
		WithArguments(sm.Full("127.0.0.1"))

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
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithDestinationPort(80).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessCloseChecker("curlClose").
			WithProcess(curlChecker).
			WithParent(selfChecker).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithDestinationPort(80).
			WithProtocol(tetragon.SocketProtocol_TCP).
			WithSocketType(sm.Full("connect")),
	)

	obs := getBasicTcpObserver(t, ctx, false)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	observertesthelper.ExecWGCurl(&readyWG, 10, "127.0.0.1")
	err := jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func testDisableConfigConnect4(t *testing.T, CLISwitches bool, disableConnect bool) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	if CLISwitches {
		oldEnableTCPValue := enterpriseOption.Config.EnableTCP
		enterpriseOption.Config.EnableTCP = true
		oldLayer3CLIEnableValue := enterpriseOption.Config.Layer3CLIEnable
		enterpriseOption.Config.Layer3CLIEnable = true
		t.Cleanup(func() {
			enterpriseOption.Config.EnableTCP = oldEnableTCPValue
			enterpriseOption.Config.Layer3CLIEnable = oldLayer3CLIEnableValue
		})
		layer3.EnableLayer3Progs()
	}

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	curlChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix("curl")).
		WithArguments(sm.Full("127.0.0.1"))

	execChecker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("curlExec").
			WithProcess(curlChecker).
			WithParent(selfChecker),
	)

	connectChecker := ec.NewUnorderedEventChecker(
		ec.NewProcessConnectChecker("curlConnect").
			WithProcess(curlChecker).
			WithParent(selfChecker).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithDestinationPort(80).
			WithProtocol(tetragon.SocketProtocol_TCP),
	)

	obs := getTcpObserverDisableEvents(t, ctx, false, CLISwitches, disableConnect, true, true, true)
	if CLISwitches {
		layer3.RunLayer3Progs(ctx)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	observertesthelper.ExecWGCurl(&readyWG, 10, "127.0.0.1")

	// Regardless of enabled/disabled network events, we should exepct the exec events
	err := jsonchecker.JsonTestCheck(t, execChecker)
	assert.NoError(t, err)

	// If connect events are disabled then expect checker failure
	err = jsonchecker.JsonTestCheckExpect(t, connectChecker, disableConnect)
	assert.NoError(t, err)
}

func TestDisableConnectEvent4CLI(t *testing.T) {
	testDisableConfigConnect4(t, true, true)
}

func TestNoDisableConnectEvent4CLI(t *testing.T) {
	testDisableConfigConnect4(t, true, false)
}

func TestDisableConnectEvent4NoCLI(t *testing.T) {
	testDisableConfigConnect4(t, false, true)
}

func TestNoDisableConnectEvent4NoCLI(t *testing.T) {
	testDisableConfigConnect4(t, false, false)
}

func TestExecEventClone4(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	orig := "nc.openbsd"
	server := orig
	client := server
	if _, err := exec.LookPath(server); err != nil {
		server = "nc.openbsd"
		client = server

		if _, err := exec.LookPath(server); err != nil {
			t.Fatalf("Binary server=%q,client=%q doesn't exist on host machine, cannot continue",
				server, client)
		}

		t.Logf("Using server=%v,client=%v instead of original programs (server=%v,client=%v)",
			server, client, orig, orig)
	}

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncSrvChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-nvlp 8081"))

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

	obs := getBasicTcpObserver(t, ctx, false)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdServer := exec.Command(server, "-nvlp", "8081")
	assert.NoError(t, cmdServer.Start())
	time.Sleep(1000 * time.Millisecond)
	cmdClient := exec.Command(client, "127.0.0.1", "8081")
	assert.NoError(t, cmdClient.Start())

	err := jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)

	killAndWaitCommand(t, cmdServer)
	killAndWaitCommand(t, cmdClient)
}

func TestExistingListenEvent4(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	server := getNCCommand(t, "nc.openbsd")

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

	/* Start server before creating obs */
	cmdServer := exec.Command(server, "-nvlp", "8082", "-s", "0.0.0.0")
	assert.NoError(t, cmdServer.Start())

	time.Sleep(1000 * time.Millisecond)

	/* Create obs */
	obs := getBasicTcpObserver(t, ctx, false)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()
	killAndWaitCommand(t, cmdServer)

	err := jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestExistingAcceptEvent4(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	server := getNCCommand(t, "nc.openbsd")
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

	/* Start server before creating obs */
	cmdServer := exec.Command(server, "-nvlp", "8083", "-s", "0.0.0.0")
	assert.NoError(t, cmdServer.Start())
	time.Sleep(1000 * time.Millisecond)

	/* Create obs */
	obs := getBasicTcpObserver(t, ctx, false)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	time.Sleep(1000 * time.Millisecond)
	cmdClient := exec.Command(client, "127.0.0.1", "8083")
	assert.NoError(t, cmdClient.Start())
	time.Sleep(1000 * time.Millisecond)

	err := jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)

	killAndWaitCommand(t, cmdServer)
	killAndWaitCommand(t, cmdClient)
}

func TestExistingRootCWDListenEvent4(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	server := getNCCommand(t, "nc.openbsd")

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

	path, err := os.Getwd()
	if err != nil {
		t.Fail()
	}

	/* Start server in '/' before creating observer */
	os.Chdir("/")
	cmdServer := exec.Command(server, "-nvlp", "8094", "-s", "0.0.0.0")
	assert.NoError(t, cmdServer.Start())
	os.Chdir(path)

	/* Create obs */
	obs := getBasicTcpObserver(t, ctx, false)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()
	killAndWaitCommand(t, cmdServer)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestListenAcceptClose4(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	server := getNCCommand(t, "nc.openbsd")
	client := server

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-nvlp 8085"))

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
			WithPort(8085).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessAcceptChecker("ncAccept").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithSourcePort(8085).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessCloseChecker("ncClose").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("0.0.0.0")).
			WithSourcePort(8085).
			WithProtocol(tetragon.SocketProtocol_TCP).
			WithSocketType(sm.Full("listen")),
		// TODO: it would be good if we could also check the close event on
		// the accept socket, but it goes into TIME_WAIT and then
		// eventually close and I don't want to wait for it. So we need
		// some go way to close the sockets.
	)

	obs := getBasicTcpObserver(t, ctx, false)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdServer := exec.Command(server, "-nvlp", "8085")
	assert.NoError(t, cmdServer.Start())
	time.Sleep(1000 * time.Millisecond)
	cmdClient := exec.Command(client, "127.0.0.1", "8085")
	assert.NoError(t, cmdClient.Start())

	time.Sleep(1000 * time.Millisecond)

	killAndWaitCommand(t, cmdServer)
	killAndWaitCommand(t, cmdClient)

	err := jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func testDisableConfigListenAcceptClose4(t *testing.T, CLISwitches bool, disableListen bool, disableAccept bool, disableClose bool) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	if CLISwitches {
		oldEnableTCPValue := enterpriseOption.Config.EnableTCP
		enterpriseOption.Config.EnableTCP = true
		oldLayer3CLIEnableValue := enterpriseOption.Config.Layer3CLIEnable
		enterpriseOption.Config.Layer3CLIEnable = true
		t.Cleanup(func() {
			enterpriseOption.Config.EnableTCP = oldEnableTCPValue
			enterpriseOption.Config.Layer3CLIEnable = oldLayer3CLIEnableValue
		})
		layer3.EnableLayer3Progs()
	}

	server := getNCCommand(t, "nc.openbsd")
	client := server
	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-nvlp 8086"))

	execChecker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("ncExec").
			WithProcess(ncChecker).
			WithParent(selfChecker),
	)

	listenChecker := ec.NewUnorderedEventChecker(
		ec.NewProcessListenChecker("ncListen").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithIp(sm.Full("0.0.0.0")).
			WithPort(8086).
			WithProtocol(tetragon.SocketProtocol_TCP),
	)
	acceptChecker := ec.NewUnorderedEventChecker(
		ec.NewProcessAcceptChecker("ncAccept").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithSourcePort(8086).
			WithProtocol(tetragon.SocketProtocol_TCP),
	)
	closeChecker := ec.NewUnorderedEventChecker(
		ec.NewProcessCloseChecker("ncClose").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithSourcePort(8086).
			WithProtocol(tetragon.SocketProtocol_TCP).
			WithSocketType(sm.Full("accept")),
	)

	obs := getTcpObserverDisableEvents(t, ctx, false, CLISwitches, true, disableClose, disableAccept, disableListen)
	if CLISwitches {
		layer3.RunLayer3Progs(ctx)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdServer := exec.Command(server, "-nvlp", "8086")
	assert.NoError(t, cmdServer.Start())
	time.Sleep(1000 * time.Millisecond)
	cmdClient := exec.Command(client, "127.0.0.1", "8086")
	assert.NoError(t, cmdClient.Start())

	time.Sleep(1000 * time.Millisecond)

	killAndWaitCommand(t, cmdServer)
	killAndWaitCommand(t, cmdClient)

	// Regardless of enabled/disabled network events, we should exepct the exec events
	err := jsonchecker.JsonTestCheck(t, execChecker)
	assert.NoError(t, err)

	listenErr := jsonchecker.JsonTestCheckExpect(t, listenChecker, disableListen)
	assert.NoError(t, listenErr)

	acceptErr := jsonchecker.JsonTestCheckExpect(t, acceptChecker, disableAccept)
	assert.NoError(t, acceptErr)

	closeErr := jsonchecker.JsonTestCheckExpect(t, closeChecker, disableClose)
	assert.NoError(t, closeErr)
}

func TestDisableListenAcceptClose4CLI(t *testing.T) {
	testDisableConfigListenAcceptClose4(t, true, true, true, true)
}

func TestNoDisableListenAcceptClose4CLI(t *testing.T) {
	testDisableConfigListenAcceptClose4(t, true, false, false, false)
}

func TestDisableListenAcceptClose4NoCLI(t *testing.T) {
	testDisableConfigListenAcceptClose4(t, false, true, true, true)
}

func TestNoDisableListenAcceptClose4NoCLI(t *testing.T) {
	testDisableConfigListenAcceptClose4(t, false, false, false, false)
}

func TestDockerExistingListenEvent4(t *testing.T) {
	if err := exec.Command("docker", "version").Run(); err != nil {
		t.Skipf("docker not available. skipping test: %s", err)
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	// Try removing container first as an existing one will cause the following line to fail.
	exec.Command("docker", "rm", "--force", "fgs-test-server").Run()
	/* Start server before creating obs */
	docker.Run(t, "--name", "fgs-test-server", "--entrypoint", "nc", alpineCurlImage, "-nvlp", "8087", "-s", "0.0.0.0")
	observertesthelper.WaitForProcess("nc -nvlp 8087 -s 0.0.0.0")
	time.Sleep(2 * time.Second)

	/* Create obs */
	obs := getBasicTcpObserver(t, ctx, true)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

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

	err := jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestDockerListenConnect4(t *testing.T) {
	if err := exec.Command("docker", "version").Run(); err != nil {
		t.Skipf("docker not available. skipping test: %s", err)
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	obs := getBasicTcpObserver(t, ctx, true)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	// Try removing container first as an existing one will cause the following line to fail.
	exec.Command("docker", "rm", "--force", "fgs-test-server").Run()
	serverDockerID := docker.Run(t, "--name", "fgs-test-server", "--entrypoint", "nc", alpineCurlImage, "-nvlp", "8088", "-s", "0.0.0.0")
	time.Sleep(1 * time.Second)
	clientDockerID := docker.Run(t, "--link", "fgs-test-server", "--entrypoint", "nc", alpineCurlImage, "-p", "9876", "fgs-test-server", "8088")

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

	time.Sleep(1 * time.Second)

	err := jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

const TCPBUFSIZE, TCPBUFVAR = 1024, 256
const tcpHostname = "127.0.0.1"
const tcpPortno = 31337
const tcpProtocol = "tcp4"

var watermarksQuit = false

func handleSes(ses net.Conn) {
	buf := make([]byte, 2*TCPBUFSIZE)
	quit := false
	ses.SetDeadline(time.Now().Add(200 * time.Millisecond))
	for !quit && !watermarksQuit {
		_, err := ses.Read(buf)
		if err != nil {
			opErr, ok := err.(*net.OpError)
			if !ok || !opErr.Timeout() {
				quit = true
			}
		}
	}
}

func runTcpServer() {

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM)
	conn, err := net.Listen(tcpProtocol, fmt.Sprintf("%s:%d", tcpHostname, tcpPortno))
	if err != nil {
		fmt.Printf("NotReady: %s", err)
		panic(err)
	}
	go func() {
		sig := <-sigs
		if sig == syscall.SIGTERM {
			conn.Close()
			watermarksQuit = true
			// Give chance for sockets to gracefully close
			time.Sleep(500 * time.Millisecond)
			os.Exit(0)
		}
	}()

	fmt.Printf("Ready\n")

	for {
		ses, err := conn.Accept()
		if err != nil {
			panic(err)
		}
		go handleSes(ses)
	}
}

func tcpSendData(socket net.Conn, buf []byte) {
	bufLen := rand.Intn(TCPBUFVAR) - (TCPBUFVAR / 2) + TCPBUFSIZE
	_, err := socket.Write(buf[0:bufLen])
	if err != nil {
		fmt.Printf("ERROR writing to socket\n")
		panic(err)
	}
}

func runTcpClient() {
	baselineRate := 5
	burstRate := 10
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

	buf := make([]byte, TCPBUFSIZE+TCPBUFVAR)
	randReader := bufio.NewReader(randFile)
	_, err = randReader.Read(buf)
	if err != nil {
		fmt.Printf("ERROR reading urandom\n")
		panic(err)
	}
	randFile.Close()

	socket, err := net.Dial(tcpProtocol, fmt.Sprintf("%s:%d", tcpHostname, tcpPortno))
	if err != nil {
		fmt.Printf("ERROR dialing socket\n")
		panic(err)
	}

	for i := 0; i < numBursts; i++ {
		for j := 0; j < (baselineDuration * baselineRate); j++ {
			tcpSendData(socket, buf)
			time.Sleep(baselineWait * time.Microsecond)
		}
		for j := 0; j < (burstDuration * burstRate); j++ {
			tcpSendData(socket, buf)
			time.Sleep(burstWait * time.Microsecond)
		}
	}

	socket.Close()
}

func testTcpWatermarks(t *testing.T, legacy bool) {
	// timing related tests are unreliable currently. In lieu of a solution, let's
	// disable these tests.
	t.Skipf("Test disabled due to unreliable timing in CI")

	bpf.CheckOrMountCgroup2()

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))
	clientProcess := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary)).
		WithArguments(sm.Full("-tcpClient"))
	serverProcess := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary)).
		WithArguments(sm.Full("-tcpServer"))

	var checker *ec.UnorderedEventChecker

	if legacy {
		checker = ec.NewUnorderedEventChecker(
			ec.NewProcessExecChecker("clientExec").
				WithProcess(clientProcess).
				WithParent(selfChecker),
			ec.NewProcessNetworkBurstChecker("burstEgressStart").
				WithProcess(clientProcess).
				WithParent(selfChecker).
				WithProtocol(sm.Full("TCP")).
				WithDirection(sm.Full("egress")).
				WithBurstState(sm.Full("start")),
			ec.NewProcessNetworkBurstChecker("burstEgressEnd").
				WithProcess(clientProcess).
				WithParent(selfChecker).
				WithProtocol(sm.Full("TCP")).
				WithDirection(sm.Full("egress")).
				WithBurstState(sm.Full("end")),
			ec.NewProcessExecChecker("serverExec").
				WithProcess(serverProcess).
				WithParent(selfChecker),
			ec.NewProcessExitChecker("serverExit").
				WithProcess(serverProcess).
				WithParent(selfChecker),
		)
	} else {
		checker = ec.NewUnorderedEventChecker(
			ec.NewProcessExecChecker("clientExec").
				WithProcess(clientProcess).
				WithParent(selfChecker),
			ec.NewProcessNetworkWatermarkChecker("burstEgressStart").
				WithProcess(clientProcess).
				WithParent(selfChecker).
				WithProtocol(sm.Full("TCP")).
				WithWatermarksType(sm.Full("burst")).
				WithDirection(sm.Full("egress")).
				WithWatermarksState(sm.Full("start")),
			ec.NewProcessNetworkWatermarkChecker("burstEgressEnd").
				WithProcess(clientProcess).
				WithParent(selfChecker).
				WithProtocol(sm.Full("TCP")).
				WithWatermarksType(sm.Full("burst")).
				WithDirection(sm.Full("egress")).
				WithWatermarksState(sm.Full("end")),
			ec.NewProcessNetworkWatermarkChecker("dipEgressStart").
				WithProcess(clientProcess).
				WithParent(selfChecker).
				WithProtocol(sm.Full("TCP")).
				WithWatermarksType(sm.Full("dip")).
				WithDirection(sm.Full("egress")).
				WithWatermarksState(sm.Full("start")),
			ec.NewProcessNetworkWatermarkChecker("dipEgressEnd").
				WithProcess(clientProcess).
				WithParent(selfChecker).
				WithProtocol(sm.Full("TCP")).
				WithWatermarksType(sm.Full("dip")).
				WithDirection(sm.Full("egress")).
				WithWatermarksState(sm.Full("end")),
			ec.NewProcessExecChecker("serverExec").
				WithProcess(serverProcess).
				WithParent(selfChecker),
			ec.NewProcessExitChecker("serverExit").
				WithProcess(serverProcess).
				WithParent(selfChecker),
			ec.NewProcessNetworkWatermarkChecker("burstIngressStart").
				WithProcess(serverProcess).
				WithParent(selfChecker).
				WithProtocol(sm.Full("TCP")).
				WithWatermarksType(sm.Full("burst")).
				WithDirection(sm.Full("ingress")).
				WithWatermarksState(sm.Full("start")),
			ec.NewProcessNetworkWatermarkChecker("burstIngressEnd").
				WithProcess(serverProcess).
				WithParent(selfChecker).
				WithProtocol(sm.Full("TCP")).
				WithWatermarksType(sm.Full("burst")).
				WithDirection(sm.Full("ingress")).
				WithWatermarksState(sm.Full("end")),
			ec.NewProcessNetworkWatermarkChecker("dipIngressStart").
				WithProcess(serverProcess).
				WithParent(selfChecker).
				WithProtocol(sm.Full("TCP")).
				WithWatermarksType(sm.Full("dip")).
				WithDirection(sm.Full("ingress")).
				WithWatermarksState(sm.Full("start")),
			ec.NewProcessNetworkWatermarkChecker("dipIngressEnd").
				WithProcess(serverProcess).
				WithParent(selfChecker).
				WithProtocol(sm.Full("TCP")).
				WithWatermarksType(sm.Full("dip")).
				WithDirection(sm.Full("ingress")).
				WithWatermarksState(sm.Full("end")),
		)
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	if legacy {
		if err := observertesthelper.WriteConfigFile(testConfigFile, tcpConfigLegacy); err != nil {
			t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
		}
	} else {
		if err := observertesthelper.WriteConfigFile(testConfigFile, tcpConfig); err != nil {
			t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
		}
	}

	dfltBase := base.GetInitialSensor()
	obs, err := enterpriseoth.GetDefaultObserverWithBase(t, ctx, dfltBase, testConfigFile, runner.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	serverCmd := exec.Command(os.Args[0], "-tcpServer")
	serverOutput, err := serverCmd.StdoutPipe()
	if err != nil {
		t.Fatalf("ERROR Could not connect to server output pipe: '%s'", err)
	}
	serverCmd.Stderr = os.Stderr

	err = serverCmd.Start()
	if err != nil {
		t.Fatalf("ERROR Cannot start server: '%s'", err)
	}

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
			t.Fatal("received empty line from TCP server")
		}
		if strings.HasPrefix(string(line), "NotReady") {
			t.Fatalf("TCP server failed to start: '%s'", string(line))
		}
	}

	serverPid := uint32(serverCmd.Process.Pid)

	watermarksMapFile := filepath.Join(bpf.MapPrefixPath(), networkWatermarksEvents.ProcessNetworkWatermarksMapName)
	m, err := ebpf.LoadPinnedMap(watermarksMapFile, nil)
	if err != nil {
		t.Fatalf("ERROR Cannot open map file: '%s'", err)
	}
	defer m.Close()
	processKey := &networkWatermarksEvents.ProcessNetworkWatermarksKey{Key: networkWatermarksEvents.PidToWatermarksKey(serverPid, syscall.IPPROTO_TCP, 0)}
	var processValue networkWatermarksEvents.ProcessNetworkWatermarksValue
	err = m.Lookup(processKey, &processValue)
	if err == nil {
		t.Fatal("ERROR Server process in network watermarks map before traffic")
	}

	clientCmd := exec.Command(os.Args[0], "-tcpClient")
	clientCmd.Stdout = os.Stderr
	clientCmd.Stderr = os.Stderr
	err = clientCmd.Run()
	if err != nil {
		t.Fatalf("ERROR Cannot start client: '%s'", err)
	}

	err = m.Lookup(processKey, &processValue)
	if err != nil {
		t.Fatalf("ERROR Server process not in network watermarks map: '%s'", err)
	}

	if serverCmd != nil {
		serverProcess := serverCmd.Process
		if serverProcess != nil {
			serverProcess.Kill()
			serverProcess.Wait()
		} else {
			t.Fatal("ERROR serverProcess is nil")
		}
	} else {
		t.Fatal("ERROR serverCmd is nil")
	}

	quit := false
	for !quit {
		_, err = os.Stat(fmt.Sprintf("/proc/%d", serverPid))
		if err != nil {
			quit = true
		}
		time.Sleep(10 * time.Millisecond)
	}

	// the burst map record is sure to be removed after exit event is
	// received, let's wait for that and do the lookup check after

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)

	err = m.Lookup(processKey, &processValue)
	if err == nil {
		t.Fatal("ERROR Server process in network watermarks map after exit")
	}
}

func TestTcpBurst(t *testing.T) {
	testTcpWatermarks(t, true)
}

func TestTcpWatermarks(t *testing.T) {
	testTcpWatermarks(t, false)
}

func TestNamespaces(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	rootNs := namespace.GetCurrentNamespace()
	nsChecker := ec.NewNamespacesChecker().FromNamespaces(rootNs)

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary)).
		WithNs(nsChecker)

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
	)

	obs, err := enterpriseoth.GetDefaultObserver(t, ctx, runner.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}

	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()
	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

// Note following test uses port 8082 instead of port 8081. This is primarily so that it
// can be easily tracked for debugging.
func TestDetectLatency4(t *testing.T) {
	// timing related tests are unreliable currently. In lieu of a solution, let's
	// disable these tests.
	t.Skipf("Test disabled due to unreliable timing in CI")
	if !utils.CGroupSKBAvailable() {
		t.Skipf("This test requires CGroup/SKB, skipping")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	server := getNCCommand(t, "nc.openbsd")
	client := server

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-nvlp 8082"))

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
		ec.NewProcessAcceptChecker("ncAccept").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithSourcePort(8082).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessCloseChecker("ncClose").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithSourcePort(8082).
			WithProtocol(tetragon.SocketProtocol_TCP).
			WithSocketType(sm.Full("accept")).
			WithStats(ec.NewSocketStatsChecker().
				WithLatency(ec.NewHistogramChecker().
					WithBuckets(ec.NewHistogramBucketListMatcher().
						WithValues(ec.NewHistogramBucketChecker().
							WithPercentile(1))))), // Don't check count as it can vary unfortunately
	)

	obs := getTcpObserverWithLatencyDetection(t, ctx, false)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdServer := exec.Command(server, "-nvlp", "8082")
	assert.NoError(t, cmdServer.Start())
	time.Sleep(1000 * time.Millisecond)

	cmdClient := exec.Command(client, "127.0.0.1", "8082")
	stdin, err := cmdClient.StdinPipe()
	assert.NoError(t, err)
	assert.NoError(t, cmdClient.Start())
	_, err = stdin.Write([]byte("hello"))
	assert.NoError(t, err)
	time.Sleep(1000 * time.Millisecond)

	killAndWaitCommand(t, cmdClient)
	killAndWaitCommand(t, cmdServer)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestDetectRTT4(t *testing.T) {
	// timing related tests are unreliable currently. In lieu of a solution, let's
	// disable these tests.
	t.Skipf("Test disabled due to unreliable timing in CI")

	if !utils.RTTHookAvailable() {
		t.Skipf("RTT hooks are unavailable, skipping")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	server := getNCCommand(t, "nc.openbsd")
	client := server

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-nvlp 8083"))

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
		ec.NewProcessCloseChecker("ncClose").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithSourcePort(8083).
			WithProtocol(tetragon.SocketProtocol_TCP).
			WithSocketType(sm.Full("accept")).
			WithStats(ec.NewSocketStatsChecker().
				WithRtt(ec.NewHistogramChecker().
					WithBuckets(ec.NewHistogramBucketListMatcher().
						WithValues(ec.NewHistogramBucketChecker().
							WithPercentile(1))))))

	obs := getTcpObserverWithRTTDetection(t, ctx, false)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdServer := exec.Command(server, "-nvlp", "8083")
	assert.NoError(t, cmdServer.Start())
	time.Sleep(1000 * time.Millisecond)

	cmdClient := exec.Command(client, "127.0.0.1", "8083")
	stdin, err := cmdClient.StdinPipe()
	assert.NoError(t, err)
	assert.NoError(t, cmdClient.Start())
	_, err = stdin.Write([]byte("hello"))
	assert.NoError(t, err)
	time.Sleep(1000 * time.Millisecond)

	killAndWaitCommand(t, cmdClient)
	killAndWaitCommand(t, cmdServer)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestDetectSRTT4(t *testing.T) {
	// timing related tests are unreliable currently. In lieu of a solution, let's
	// disable these tests.
	t.Skipf("Test disabled due to unreliable timing in CI")

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	server := getNCCommand(t, "nc.openbsd")
	client := server

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-nvlp 8184"))

	serverStatsChecker := ec.NewProcessSockStatsChecker("serverStats").
		WithProcess(ncChecker).
		WithParent(selfChecker).
		WithSocket(ec.NewSockInfoChecker().
			WithProtocol(tetragon.SocketProtocol_TCP).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithSourcePort(8184))

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
			WithPort(8184).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessAcceptChecker("ncAccept").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithSourcePort(8184).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessCloseChecker("ncClose").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithSourcePort(8184).
			WithProtocol(tetragon.SocketProtocol_TCP).
			WithSocketType(sm.Full("accept")))

	statsChecker := &ec.FnEventChecker{
		NextCheckFn: func(event_ ec.Event, _ *logrus.Logger) (bool, error) {
			event, ok := event_.(*tetragon.ProcessSockStats)
			if !ok {
				return false, fmt.Errorf("event is not a sockstats event")
			}

			if event.Stats == nil {
				return false, fmt.Errorf("event has no stats field")
			}

			if serverStatsChecker.Check(event) == nil {
				if event.Stats.Srtt <= 0 {
					return false, fmt.Errorf("event SRTT <= 0")
				}
				if event.Stats.Srtt > 1000 {
					return false, fmt.Errorf("event SRTT > 1000us")
				}
				return false, nil
			}

			return false, fmt.Errorf("sockstats event is not from server")
		},
		FinalCheckFn: func(_ *logrus.Logger) error {
			return nil
		},
	}

	obs := getTcpObserverWithRTTDetection(t, ctx, false)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdServer := exec.Command(server, "-nvlp", "8184")
	assert.NoError(t, cmdServer.Start())
	time.Sleep(1000 * time.Millisecond)

	cmdClient := exec.Command(client, "127.0.0.1", "8184")
	stdin, err := cmdClient.StdinPipe()
	assert.NoError(t, err)
	assert.NoError(t, cmdClient.Start())
	_, err = stdin.Write([]byte("hello"))
	assert.NoError(t, err)
	time.Sleep(1000 * time.Millisecond)

	killAndWaitCommand(t, cmdClient)
	killAndWaitCommand(t, cmdServer)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)

	err = jsonchecker.JsonTestCheck(t, statsChecker)
	assert.NoError(t, err)
}

func TestConnectEvent6(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

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
			WithSocketType(sm.Full("connect")),
	)

	obs := getBasicTcpObserver(t, ctx, false)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	observertesthelper.ExecWGCurl(&readyWG, 10, "[::1]")
	err := jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestExecEventClone6(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	orig := "nc.openbsd"
	server := orig
	client := server
	if _, err := exec.LookPath(server); err != nil {
		server = "nc.openbsd"
		client = server

		if _, err := exec.LookPath(server); err != nil {
			t.Fatalf("Binary server=%q,client=%q doesn't exist on host machine, cannot continue",
				server, client)
		}

		t.Logf("Using server=%v,client=%v instead of original programs (server=%v,client=%v)",
			server, client, orig, orig)
	}

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncSrvChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-6nvlp 8081"))

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

	obs := getBasicTcpObserver(t, ctx, false)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdServer := exec.Command(server, "-6nvlp", "8081")
	assert.NoError(t, cmdServer.Start())
	time.Sleep(1000 * time.Millisecond)
	cmdClient := exec.Command(client, "-6", "::1", "8081")
	assert.NoError(t, cmdClient.Start())

	err := jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)

	killAndWaitCommand(t, cmdServer)
	killAndWaitCommand(t, cmdClient)
}

func TestExistingListenEvent6(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	server := getNCCommand(t, "nc.openbsd")

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

	/* Start server before creating obs */
	cmdServer := exec.Command(server, "-6nvlp", "8082", "-s", "::")
	assert.NoError(t, cmdServer.Start())

	time.Sleep(1000 * time.Millisecond)

	/* Create obs */
	obs := getBasicTcpObserver(t, ctx, false)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()
	killAndWaitCommand(t, cmdServer)

	err := jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestExistingAcceptEvent6(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	server := getNCCommand(t, "nc.openbsd")
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

	/* Start server before creating obs */
	cmdServer := exec.Command(server, "-6nvlp", "8083", "-s", "::")
	assert.NoError(t, cmdServer.Start())
	time.Sleep(1000 * time.Millisecond)

	/* Create obs */
	obs := getBasicTcpObserver(t, ctx, false)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	time.Sleep(1000 * time.Millisecond)
	cmdClient := exec.Command(client, "-6", "::1", "8083")
	assert.NoError(t, cmdClient.Start())
	time.Sleep(1000 * time.Millisecond)

	err := jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)

	killAndWaitCommand(t, cmdServer)
	killAndWaitCommand(t, cmdClient)
}

func TestExistingRootCWDListenEvent6(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	server := getNCCommand(t, "nc.openbsd")

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

	path, err := os.Getwd()
	if err != nil {
		t.Fail()
	}

	/* Start server in '/' before creating observer */
	os.Chdir("/")
	cmdServer := exec.Command(server, "-6nvlp", "8094", "-s", "::")
	assert.NoError(t, cmdServer.Start())
	os.Chdir(path)

	/* Create obs */
	obs := getBasicTcpObserver(t, ctx, false)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	killAndWaitCommand(t, cmdServer)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestListenAcceptClose6(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	server := getNCCommand(t, "nc.openbsd")
	client := server

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-6nvlp 8085"))

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

	obs := getBasicTcpObserver(t, ctx, false)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdServer := exec.Command(server, "-6nvlp", "8085")
	assert.NoError(t, cmdServer.Start())
	time.Sleep(1000 * time.Millisecond)
	cmdClient := exec.Command(client, "-6", "::1", "8085")
	assert.NoError(t, cmdClient.Start())

	time.Sleep(1000 * time.Millisecond)

	killAndWaitCommand(t, cmdServer)
	killAndWaitCommand(t, cmdClient)

	err := jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestDockerExistingListenEvent6(t *testing.T) {
	if err := exec.Command("docker", "version").Run(); err != nil {
		t.Skipf("docker not available. skipping test: %s", err)
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	// Try removing container first as an existing one will cause the following line to fail.
	exec.Command("docker", "rm", "--force", "fgs-test-server").Run()
	/* Start server before creating obs */
	docker.Run(t, "--name", "fgs-test-server", "--entrypoint", "nc", alpineCurlImage, "-nvlp", "8086", "-s", "[::]")
	observertesthelper.WaitForProcess("nc -nvlp 8086 -s [::]")
	time.Sleep(2 * time.Second)

	/* Create obs */
	obs := getBasicTcpObserver(t, ctx, true)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

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

	err := jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestDockerListenConnect6(t *testing.T) {
	if err := exec.Command("docker", "version").Run(); err != nil {
		t.Skipf("docker not available. skipping test: %s", err)
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	obs := getBasicTcpObserver(t, ctx, true)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	// Try removing container first as an existing one will cause the following line to fail.
	exec.Command("docker", "rm", "--force", "fgs-test-server").Run()
	serverDockerID := docker.Run(t, "--name", "fgs-test-server", "--entrypoint", "nc", alpineCurlImage, "-nvlp", "8087", "-s", "[::]")
	time.Sleep(1 * time.Second)
	clientDockerID := docker.Run(t, "--link", "fgs-test-server", "--entrypoint", "nc", alpineCurlImage, "-p", "9876", "fgs-test-server", "8087")

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
		WithArguments(sm.Full("-p 9876 fgs-test-server 8087")).
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

	time.Sleep(1 * time.Second)

	err := jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestDetectRTT6(t *testing.T) {
	// timing related tests are unreliable currently. In lieu of a solution, let's
	// disable these tests.
	t.Skipf("Test disabled due to unreliable timing in CI")

	if !utils.RTTHookAvailable() {
		t.Skipf("RTT hooks are unavailable, skipping")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	server := getNCCommand(t, "nc.openbsd")
	client := server

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-6nvlp 8083"))

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
		ec.NewProcessCloseChecker("ncClose").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("::1")).
			WithSourcePort(8083).
			WithProtocol(tetragon.SocketProtocol_TCP).
			WithSocketType(sm.Full("accept")).
			WithStats(ec.NewSocketStatsChecker().
				WithRtt(ec.NewHistogramChecker().
					WithBuckets(ec.NewHistogramBucketListMatcher().
						WithValues(ec.NewHistogramBucketChecker().
							WithPercentile(1))))))

	obs := getTcpObserverWithRTTDetection(t, ctx, false)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdServer := exec.Command(server, "-6nvlp", "8083")
	assert.NoError(t, cmdServer.Start())
	time.Sleep(1000 * time.Millisecond)

	cmdClient := exec.Command(client, "-6n", "::1", "8083")
	stdin, err := cmdClient.StdinPipe()
	assert.NoError(t, err)
	assert.NoError(t, cmdClient.Start())
	_, err = stdin.Write([]byte("hello"))
	assert.NoError(t, err)
	time.Sleep(1000 * time.Millisecond)

	killAndWaitCommand(t, cmdClient)
	killAndWaitCommand(t, cmdServer)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

// FIXME: net io_uring test seems to time out on ARM.
func TestDetectSRTT6(t *testing.T) {
	// timing related tests are unreliable currently. In lieu of a solution, let's
	// disable these tests.
	t.Skipf("Test disabled due to unreliable timing in CI")

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	server := getNCCommand(t, "nc.openbsd")
	client := server

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-6nvlp 8184"))

	serverStatsChecker := ec.NewProcessSockStatsChecker("serverStats").
		WithProcess(ncChecker).
		WithParent(selfChecker).
		WithSocket(ec.NewSockInfoChecker().
			WithProtocol(tetragon.SocketProtocol_TCP).
			WithSourceIp(sm.Full("::1")).
			WithDestinationIp(sm.Full("::1")).
			WithSourcePort(8184))

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
			WithPort(8184).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessAcceptChecker("ncAccept").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("::1")).
			WithSourcePort(8184).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessCloseChecker("ncClose").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("::1")).
			WithSourcePort(8184).
			WithProtocol(tetragon.SocketProtocol_TCP).
			WithSocketType(sm.Full("accept")))

	statsChecker := &ec.FnEventChecker{
		NextCheckFn: func(event_ ec.Event, _ *logrus.Logger) (bool, error) {
			event, ok := event_.(*tetragon.ProcessSockStats)
			if !ok {
				return false, fmt.Errorf("event is not a sockstats event")
			}

			if event.Stats == nil {
				return false, fmt.Errorf("event has no stats field")
			}

			if serverStatsChecker.Check(event) == nil {
				if event.Stats.Srtt <= 0 {
					return false, fmt.Errorf("event SRTT <= 0")
				}
				if event.Stats.Srtt > 1000 {
					return false, fmt.Errorf("event SRTT > 1000us")
				}
				return false, nil
			}

			return false, fmt.Errorf("sockstats event is not from server")
		},
		FinalCheckFn: func(_ *logrus.Logger) error {
			return nil
		},
	}

	obs := getTcpObserverWithRTTDetection(t, ctx, false)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdServer := exec.Command(server, "-6nvlp", "8184")
	assert.NoError(t, cmdServer.Start())
	time.Sleep(1000 * time.Millisecond)

	cmdClient := exec.Command(client, "-6n", "::1", "8184")
	stdin, err := cmdClient.StdinPipe()
	assert.NoError(t, err)
	assert.NoError(t, cmdClient.Start())
	_, err = stdin.Write([]byte("hello"))
	assert.NoError(t, err)
	time.Sleep(1000 * time.Millisecond)

	killAndWaitCommand(t, cmdClient)
	killAndWaitCommand(t, cmdServer)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)

	err = jsonchecker.JsonTestCheck(t, statsChecker)
	assert.NoError(t, err)
}

func TestIOUringAcceptEvent(t *testing.T) {
	if !utils.CGroupSKBAvailable() {
		t.Skipf("This test requires CGroup/SKB, skipping")
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "x86_64" {
		t.Skipf("Test seems to time out on ARM")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	server := testutils.RepoRootPath("contrib/tester-progs/io_uring/tcp_iouring_server")
	client := getNCCommand(t, "nc.openbsd")

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

	obs := getBasicTcpObserver(t, ctx, false)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdServer := exec.Command(server)
	serverOutput, err := cmdServer.StdoutPipe()
	require.NoError(t, err, "could not connect to server output pipe")
	cmdServer.Stderr = os.Stderr

	err = cmdServer.Start()
	require.NoError(t, err, "cannot start server")

	serverBuf := bufio.NewReader(serverOutput)
	var line []byte
	for string(line) != "Ready" {
		line, _, err = serverBuf.ReadLine()
		if err != nil {
			killAndWaitCommand(t, cmdServer)
			t.Fatal(err)
		}
		if len(line) == 0 {
			killAndWaitCommand(t, cmdServer)
			t.Fatal("received empty line from TCP server")
		}
		if strings.HasPrefix(string(line), "NotReady") {
			t.Fatalf("TCP server failed to start: '%s'", string(line))
		}
	}

	serverPid := uint32(cmdServer.Process.Pid)
	logger.GetLogger().WithField("ServerPid", serverPid).Info("Running")

	cmdClient := exec.Command(client, "127.0.0.1", "8000")
	stdin, err := cmdClient.StdinPipe()
	assert.NoError(t, err)
	assert.NoError(t, cmdClient.Start())
	_, err = stdin.Write([]byte("hello"))
	assert.NoError(t, err)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)

	killAndWaitCommand(t, cmdServer)
	killAndWaitCommand(t, cmdClient)
}

// FIXME: net io_uring test seems to time out on ARM.
func TestIOUringConnectEvent(t *testing.T) {
	if !utils.CGroupSKBAvailable() {
		t.Skipf("This test requires CGroup/SKB, skipping")
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "x86_64" {
		t.Skipf("Test seems to time out on ARM")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	client := testutils.RepoRootPath("contrib/tester-progs/io_uring/tcp_iouring_client")
	server := getNCCommand(t, "nc.openbsd")

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

	obs := getBasicTcpObserver(t, ctx, false)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdServer := exec.Command(server, "-nvlp", "8001")
	serverError, err := cmdServer.StderrPipe()
	require.NoError(t, err, "could not connect to server output pipe")
	cmdServer.Stdout = nil

	err = cmdServer.Start()
	require.NoError(t, err, "cannot start server")

	serverBuf := bufio.NewReader(serverError)
	var line []byte
	for string(line) != "Listening on 0.0.0.0 8001" {
		line, _, err = serverBuf.ReadLine()
		if err != nil {
			killAndWaitCommand(t, cmdServer)
			t.Fatal(err)
		}
		if len(line) == 0 {
			killAndWaitCommand(t, cmdServer)
			t.Fatal("received empty line from TCP server")
		}
	}

	serverPid := uint32(cmdServer.Process.Pid)
	logger.GetLogger().WithField("ServerPid", serverPid).Info("Running")

	cmdClient := exec.Command(client)
	cmdClient.Stderr = os.Stderr
	cmdClient.Stdout = os.Stdout

	err = cmdClient.Start()
	require.NoError(t, err, "cannot start client")

	err = cmdClient.Wait()
	if err != nil {
		killAndWaitCommand(t, cmdServer)
		t.Fatal(err)
	}

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)

	killAndWaitCommand(t, cmdServer)
	killAndWaitCommand(t, cmdClient)
}
