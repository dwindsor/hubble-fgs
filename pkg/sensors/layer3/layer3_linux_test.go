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
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/config/confmap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"

	enterpriseoth "github.com/isovalent/hubble-fgs/pkg/observer/observertesthelper"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	tusee "github.com/isovalent/hubble-fgs/pkg/testutils/sensors"

	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/testutil"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"
)

var (
	tcpClient           = false
	tcpServer           = false
	udpWatermarksClient = false
	udpMulticastClient  string
	udpServer           = false
)

const (
	testConfigFile  = "/tmp/hubble-tetragon.gotest.yaml"
	alpineCurlImage = "quay.io/cilium/alpine-curl:v1.6.0"
)

func init() {
	flag.BoolVar(&tcpClient, "tcpClient", false, "internal")
	flag.BoolVar(&tcpServer, "tcpServer", false, "internal")

	flag.BoolVar(&udpWatermarksClient, "udpWatermarksClient", false, "internal")
	flag.StringVar(&udpMulticastClient, "udpMulticastClient", "", "internal")
	flag.BoolVar(&udpServer, "udpServer", false, "internal")
}

func TestMain(m *testing.M) {
	bpf.CheckOrMountCgroup2()

	flag.Parse()
	if tcpServer {
		runTcpServer()
		os.Exit(0)
	}
	if tcpClient {
		runTcpClient()
		os.Exit(0)
	}
	if udpServer {
		runUdpServer()
		os.Exit(0)
	}
	if udpWatermarksClient {
		runUdpWatermarksClient()
		os.Exit(0)
	}
	if udpMulticastClient != "" {
		switch udpMulticastClient {
		case "lsegconn":
			runUdpMulticastLSEGClient(multicastTestLSEGConnID)
		case "lsegseq":
			runUdpMulticastLSEGClient(multicastTestLSEGSeq)
		case "lsegsample":
			runUdpMulticastLSEGClient(multicastTestLSEGSample)
		case "rtpconn":
			runUdpMulticastRTPClient(multicastTestRTPConnID)
		case "rtpseq":
			runUdpMulticastRTPClient(multicastTestRTPSeq)
		}
		os.Exit(0)
	}

	enterpriseOption.Config.EnableApplicationModel = true
	ec := runner.TestSensorsRun(m, "SensorLayer3")
	if ec != 0 {
		netstat()
	}
	os.Exit(ec)
}

func netstat() {
	netstat, err := exec.Command("ss", "-plantu").Output()
	if err != nil {
		netstat, err = exec.Command("netstat", "-plantu").Output()
	}
	if err == nil {
		netstats := string(netstat)
		for _, line := range strings.Split(netstats, "\n") {
			logger.GetLogger().Info(line)
		}
	} else {
		logger.GetLogger().Info("netstat failed", logfields.Error, err)
	}
}

func killAndWaitCommand(t *testing.T, cmd *exec.Cmd) {
	if cmd != nil {
		if cmd.Process != nil {
			cmd.Process.Kill()
		} else {
			t.Logf("Command %q process disappeared, skipping kill", cmd.Args[0])
		}
		_ = cmd.Wait()
	}
}

func signalAndWaitCommand(t *testing.T, cmd *exec.Cmd, signal syscall.Signal) {
	if cmd != nil {
		if cmd.Process != nil {
			cmd.Process.Signal(signal)
		} else {
			t.Logf("Command %q process disappeared, skipping kill", cmd.Args[0])
		}
		_ = cmd.Wait()
	}
}

func getNCCommand(t *testing.T, orig string) string {
	if _, err := exec.LookPath(orig); err == nil {
		return orig
	}

	server := "nc.openbsd"
	if _, err := exec.LookPath(server); err != nil {
		t.Fatalf("Binary %q doesn't exist on host machine, cannot continue", server)
	}
	t.Logf("Using %q instead of original program %q", server, orig)

	return server
}

func getSocatCommand(t *testing.T, orig string) string {
	if _, err := exec.LookPath(orig); err == nil {
		return orig
	}

	server := "socat"
	if _, err := exec.LookPath(server); err != nil {
		t.Fatalf("Binary %q doesn't exist on host machine, cannot continue", server)
	}
	t.Logf("Using %q instead of original program %q", server, orig)

	return server
}

// Note 20.0.0.0/8 is the DoD and isn't routable on the Internet
// This is included to test latency timestamps are NOT added
// to any real TCP packets.
const layer3ConfigTcp = `
apiversion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "layer3"
spec:
  parser:
    tcp:
      enable: true
      statsInterval: 20
`

const layer3ConfigTcpRtt = `
      histogram:
        enable: true
        min: 0
        max: 4000
`

const layer3ConfigRemainder = `
      watermarks:
        enable: true
        windowSize: 1000
        burstTriggerPercent: 50
        dipTriggerPercent: 10
    udp:
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
const layer3IcmpConfig = `
    icmp:
      enable: true
`

const layer3RawConfig = `
    rawsock:
      enable: true
      reportClose: true
`

const noConfig = `
apiversion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "noconfig"
spec: {}
`

func layer3Config(withRTT, withICMP, withRaw bool) string {
	c := layer3ConfigTcp
	if withRTT {
		c = c + layer3ConfigTcpRtt
	}
	c = c + layer3ConfigRemainder
	if withICMP {
		c = c + layer3IcmpConfig
	}
	if withRaw {
		c = c + layer3RawConfig
	}
	return c
}

// NB(kkourt): Function(t *testing.T, ctx context.Context) is the reasonable
// thing to do here even if revive complains.
//
//revive:disable:context-as-argument
func getLayer3Observer(t *testing.T, ctx context.Context, config string, filtered bool) *observer.Observer {
	if err := observertesthelper.WriteConfigFile(testConfigFile, config); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}

	base := base.GetInitialSensorTest(t)
	var obs *observer.Observer
	var err error
	if filtered {
		obs, err = enterpriseoth.GetDefaultObserverWithBase(t, ctx, base, testConfigFile, runner.Conf().TetragonLib, observertesthelper.WithMyPid())
	} else {
		obs, err = enterpriseoth.GetDefaultObserverWithBase(t, ctx, base, testConfigFile, runner.Conf().TetragonLib)
	}
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}
	err = confmap.UpdateTgRuntimeConf(bpf.MapPrefixPath(), os.Getpid())
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}
	return obs
}

func getNoConfigObserver(t *testing.T, ctx context.Context, filtered bool) *observer.Observer {
	return getLayer3Observer(t, ctx, noConfig, filtered)
}

func TestLoadLayer3Sensor(t *testing.T) {
	var l3Config string
	layer3.BaseLoaded = false
	rawHooksAvailable := utils.CGroupSKBAvailable() && utils.RawHooksAvailable()
	l3Config = layer3Config(utils.RTTHookAvailable(), utils.CGroupSKBAvailable(), rawHooksAvailable)
	if err := observertesthelper.WriteConfigFile(testConfigFile, l3Config); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}

	b := base.GetInitialSensorTest(t)
	sens, err := observertesthelper.GetDefaultSensorsWithBase(t, b, testConfigFile, runner.Conf().TetragonLib, observertesthelper.WithMyPid(), observertesthelper.WithKeepCollection())
	if err != nil {
		t.Fatalf("GetDefaultSensorsWithBase error: %s", err)
	}

	sensorProgs, sensorMaps := testutil.ProgsAndMaps(utils.RTTHookAvailable(), true, utils.CGroupSKBAvailable(), rawHooksAvailable)

	tusee.CheckSensorLoad(sens, sensorMaps, sensorProgs, t)

	sensi := make([]sensors.SensorIface, 0, len(sens))
	for _, s := range sens {
		sensi = append(sensi, s)
	}
	sensors.UnloadSensors(sensi)
	layer3.BaseLoaded = false
}

func ipToHexstring(addr net.IP) string {
	ret := ""
	if addr.To4() == nil {
		for i := 0; i < 4; i++ {
			for j := 3; j >= 0; j-- {
				ret += fmt.Sprintf("%02X", addr[i*4+j])
			}
		}
		return ret
	}
	addr = addr.To4()
	for i := len(addr) - 1; i >= 0; i-- {
		ret += fmt.Sprintf("%02X", addr[i])
	}
	return ret
}

func TestIpToHexstring(t *testing.T) {
	assert.Equal(t, "0100007F", ipToHexstring(net.ParseIP("127.0.0.1")))
	assert.Equal(t, "000080FE00000000FF005450563412FE", ipToHexstring(net.ParseIP("fe80::5054:ff:fe12:3456")))
}

// isSocketEstablished checks /proc for the IP address and port. If listening is true, it checks the local address:port,
// otherwise it checks the remote address:port.
func isSocketEstablished(addr net.IP, port uint16, protocol uint16, af uint16, listening bool) (bool, error) {
	netFile := "/proc/net/"
	switch protocol {
	case syscall.IPPROTO_TCP:
		netFile += "tcp"
	case syscall.IPPROTO_UDP:
		netFile += "udp"
	default:
		return false, fmt.Errorf("protocol must be IPPROTO_TCP or IPPROTO_UDP")
	}
	switch af {
	case syscall.AF_INET:
	case syscall.AF_INET6:
		netFile += "6"
	default:
		return false, fmt.Errorf("address family must be AF_INET or AF_INET6")
	}
	addrPort := ipToHexstring(addr)
	addrPort += fmt.Sprintf(":%04X", port)

	netData, err := os.ReadFile(netFile)
	if err != nil {
		return false, err
	}
	netLines := strings.Split(string(netData), "\n")
	for _, line := range netLines {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		// fields[1] is local address:port
		// fields[2] is remote address:port
		if (listening && fields[1] == addrPort) || (!listening && fields[2] == addrPort) {
			return true, nil
		}
	}
	return false, nil
}

func isSocketListening(addr net.IP, port uint16, protocol uint16, af uint16) (bool, error) {
	return isSocketEstablished(addr, port, protocol, af, true)
}

func TestIsSocketListening(t *testing.T) {
	listening, err := isSocketListening(net.ParseIP("0.0.0.0"), 9021, syscall.IPPROTO_TCP, syscall.AF_INET)
	require.NoError(t, err)
	require.False(t, listening)

	server := getNCCommand(t, "nc.openbsd")
	cmdServer := exec.Command(server, "-nvlp", "9021", "-s", "0.0.0.0")
	assert.NoError(t, cmdServer.Start())
	defer killAndWaitCommand(t, cmdServer)
	err = waitForSocketToListen(t, net.ParseIP("0.0.0.0"), 9021, syscall.IPPROTO_TCP, syscall.AF_INET)
	assert.NoError(t, err)

	listening, err = isSocketListening(net.ParseIP("0.0.0.0"), 9021, syscall.IPPROTO_TCP, syscall.AF_INET)
	require.NoError(t, err)
	require.True(t, listening)

	killAndWaitCommand(t, cmdServer)

	err = waitForListeningSocketToClose(t, net.ParseIP("0.0.0.0"), 9021, syscall.IPPROTO_TCP, syscall.AF_INET)
	require.NoError(t, err)

	listening, err = isSocketListening(net.ParseIP("0.0.0.0"), 9021, syscall.IPPROTO_TCP, syscall.AF_INET)
	require.NoError(t, err)
	require.False(t, listening)
}

func TestIsSocketConnected(t *testing.T) {
	listening, err := isSocketListening(net.ParseIP("0.0.0.0"), 9022, syscall.IPPROTO_TCP, syscall.AF_INET)
	require.NoError(t, err)
	require.False(t, listening)

	server := getNCCommand(t, "nc.openbsd")
	client := server
	cmdServer := exec.Command(server, "-nvlp", "9022", "-s", "0.0.0.0")
	stdout, err := cmdServer.StdoutPipe()
	assert.NoError(t, err)
	assert.NoError(t, cmdServer.Start())
	err = waitForSocketToListen(t, net.ParseIP("0.0.0.0"), 9022, syscall.IPPROTO_TCP, syscall.AF_INET)
	assert.NoError(t, err)
	cmdClient := exec.Command(client, "127.0.0.1", "9022")
	stdin, err := cmdClient.StdinPipe()
	assert.NoError(t, err)
	assert.NoError(t, cmdClient.Start())

	err = waitForSocketToListen(t, net.ParseIP("127.0.0.1"), 9022, syscall.IPPROTO_TCP, syscall.AF_INET)
	assert.NoError(t, err)

	sendData(t, stdin, "hello")
	waitForData(t, stdout, "hello")

	killAndWaitCommand(t, cmdServer)
	killAndWaitCommand(t, cmdClient)

	// Wait for the connected server socket to close
	err = waitForListeningSocketToClose(t, net.ParseIP("127.0.0.1"), 9022, syscall.IPPROTO_TCP, syscall.AF_INET)
	require.NoError(t, err)
	listening, err = isSocketListening(net.ParseIP("127.0.0.1"), 9022, syscall.IPPROTO_TCP, syscall.AF_INET)
	require.NoError(t, err)
	require.False(t, listening)

	// Wait for the listening server socket to close
	zeroaddr := net.ParseIP("0.0.0.0")
	err = waitForListeningSocketToClose(t, zeroaddr, 9022, syscall.IPPROTO_TCP, syscall.AF_INET)
	require.NoError(t, err)
	listening, err = isSocketListening(net.ParseIP("0.0.0.0"), 9022, syscall.IPPROTO_TCP, syscall.AF_INET)
	require.NoError(t, err)
	require.False(t, listening)

	// Wait for the connected client socket to close
	err = waitForConnectedSocketToClose(t, net.ParseIP("127.0.0.1"), 9022, syscall.IPPROTO_TCP, syscall.AF_INET)
	require.NoError(t, err)
	listening, err = isSocketConnected(net.ParseIP("127.0.0.1"), 9022, syscall.IPPROTO_TCP, syscall.AF_INET)
	require.NoError(t, err)
	require.False(t, listening)
}

func waitForSocketToListen(t *testing.T, addr net.IP, port uint16, protocol uint16, af uint16) error {
	t.Logf("Waiting for socket to listen: address: %s, port: %d", addr, port)
	sockListening, err := isSocketListening(addr, port, protocol, af)
	if err != nil {
		t.Logf("isSocketListening failed: %s", err)
		return err
	}
	for !sockListening {
		sockListening, err = isSocketListening(addr, port, protocol, af)
		if err != nil {
			return err
		}
		// The intention of this millisleep is to allow CPU relaxing, task switching, etc
		// so that hopefully some amount of time has passed between checks, mainly just to
		// reduce churn.
		time.Sleep(time.Millisecond)
	}
	return nil
}

func waitForListeningSocketToClose(t *testing.T, addr net.IP, port uint16, protocol uint16, af uint16) error {
	t.Logf("Waiting for socket to close: address: %s, port: %d", addr, port)
	sockListening, err := isSocketListening(addr, port, protocol, af)
	if err != nil {
		t.Logf("isSocketListening failed: %s", err)
		return err
	}
	for sockListening {
		sockListening, err = isSocketListening(addr, port, protocol, af)
		if err != nil {
			return err
		}
		// The intention of this millisleep is to allow CPU relaxing, task switching, etc
		// so that hopefully some amount of time has passed between checks, mainly just to
		// reduce churn.
		time.Sleep(time.Millisecond)
	}
	return nil
}

func isSocketConnected(addr net.IP, port uint16, protocol uint16, af uint16) (bool, error) {
	return isSocketEstablished(addr, port, protocol, af, false)
}

func waitForConnectedSocketToClose(t *testing.T, addr net.IP, port uint16, protocol uint16, af uint16) error {
	t.Logf("Waiting for socket to close: address: %s, port: %d", addr, port)
	sockConnected, err := isSocketConnected(addr, port, protocol, af)
	if err != nil {
		t.Logf("isSocketConnected failed: %s", err)
		return err
	}
	for sockConnected {
		sockConnected, err = isSocketConnected(addr, port, protocol, af)
		if err != nil {
			return err
		}
		// The intention of this millisleep is to allow CPU relaxing, task switching, etc
		// so that hopefully some amount of time has passed between checks, mainly just to
		// reduce churn.
		time.Sleep(time.Millisecond)
	}
	return nil
}

func waitAndCheckForSocketsToClose(t *testing.T, checker *ec.UnorderedEventChecker, addr net.IP, port uint16, protocol uint16, af uint16) error {
	// Wait for the listening socket to close. The listening socket should not care for any TIME_WAIT-like states
	// because it only listens, and therefore should close straight away. This wait will a) ensure that happened and
	// b) cause a small delay during which hopefully other things occurred.
	// We don't want to wait for the client or server sockets because they could go into TIME_WAIT-like states and it
	// appears that we can still get the events we need when that happens. Instead we'll wait for those if we are
	// missing events.
	err := waitForListeningSocketToClose(t, net.ParseIP("0.0.0.0"), port, protocol, af)
	if err != nil {
		return fmt.Errorf("waitForListeningSocketToClose (listener) failed: '%s'", err)
	}

	err = jsonchecker.JsonTestCheck(t, checker)
	if err == nil {
		return nil
	}

	// Let's wait for the sockets to close. This is expensive so we only do this if we really have to.
	// Note, it takes about the same amount of time to wait for both sockets as to wait for one, and there
	// is minimal benefit in checking the events between the two or choosing one to do first over the other.
	err = waitForListeningSocketToClose(t, addr, port, protocol, af)
	if err != nil {
		return fmt.Errorf("waitForListeningSocketToClose (accepted) failed: '%s'", err)
	}
	err = waitForConnectedSocketToClose(t, addr, port, protocol, af)
	if err != nil {
		return fmt.Errorf("waitForConnectedSocketToClose failed: '%s'", err)
	}

	return jsonchecker.JsonTestCheck(t, checker)
}

func sendData(t *testing.T, stdin io.WriteCloser, msg string) {
	_, err := stdin.Write([]byte(msg))
	assert.NoError(t, err)
}

func waitForData(t *testing.T, stdout io.ReadCloser, msg string) {
	rx := make([]byte, 5)
	for !bytes.Equal(rx, []byte(msg)) {
		_, err := stdout.Read(rx)
		t.Logf("read [%x] '%s'", rx, string(rx))
		require.NoError(t, err)
	}
}
