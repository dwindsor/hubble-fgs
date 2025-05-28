//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

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
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/config/confmap"
	enterpriseoth "github.com/isovalent/hubble-fgs/pkg/observer/observertesthelper"
	tusee "github.com/isovalent/hubble-fgs/pkg/testutils/sensors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/testutil"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"
)

var (
	tcpClient           = false
	tcpServer           = false
	udpWatermarksClient = false
	udpLayer7Client     = false
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
	flag.BoolVar(&udpLayer7Client, "udpLayer7Client", false, "internal")
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
	if udpLayer7Client {
		runUdpLayer7Client()
		os.Exit(0)
	}

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
		logger.GetLogger().WithError(err).Info("netstat failed")
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
			syscall.Kill(cmd.Process.Pid, signal)
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

// Subtest definitions.
type basicTestFn func(gt *testing.T, t *testing.T, readyWG *sync.WaitGroup)
type basicTest struct {
	name string
	f    basicTestFn
}

// NB(kkourt): Function(t *testing.T, ctx context.Context) is the reasonable
// thing to do here even if revive complains.
//
//revive:disable:context-as-argument
func getLayer3Observer(t *testing.T, ctx context.Context, config string, filtered bool) *observer.Observer {
	if err := observertesthelper.WriteConfigFile(testConfigFile, config); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}

	base := base.GetInitialSensor()
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
	rawHooksAvailable := utils.CGroupSKBAvailable() && utils.RawHooksAvailable()
	l3Config = layer3Config(utils.RTTHookAvailable(), utils.CGroupSKBAvailable(), rawHooksAvailable)
	if err := observertesthelper.WriteConfigFile(testConfigFile, l3Config); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}

	b := base.GetInitialSensor()
	sens, err := observertesthelper.GetDefaultSensorsWithBase(t, b, testConfigFile, runner.Conf().TetragonLib, observertesthelper.WithMyPid())
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
}

func ipToHexstring(addr net.IP) string {
	ret := ""
	if addr.To4() == nil {
		for i := 0; i < 4; i++ {
			for j := 3; j >= 0; j-- {
				ret += fmt.Sprintf("%02x", addr[i*4+j])
			}
		}
		return ret
	}
	addr = addr.To4()
	for i := len(addr) - 1; i >= 0; i-- {
		ret += fmt.Sprintf("%02x", addr[i])
	}
	return ret
}

func isSocketListening(t *testing.T, addr net.IP, port uint16, protocol uint16, af uint16) (bool, error) {
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
	t.Logf("Looking in file: %s for address:port: %s", netFile, addrPort)

	netData, err := os.ReadFile(netFile)
	if err != nil {
		return false, err
	}
	netLines := strings.Split(string(netData), "\n")
	for _, line := range netLines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		// fields[1] is local address:port
		if fields[1] == addrPort {
			return true, nil
		}
	}
	return false, nil
}

func waitForSocketToListen(t *testing.T, addr net.IP, port uint16, protocol uint16, af uint16) error {
	t.Logf("Waiting for socket to listen: address: %s, port: %d", addr, port)
	sockListening, err := isSocketListening(t, addr, port, protocol, af)
	if err != nil {
		t.Logf("isSocketListening failed: %s", err)
		return err
	}
	for !sockListening {
		sockListening, err = isSocketListening(t, addr, port, protocol, af)
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

func waitForSocketsToClose(t *testing.T, addr net.IP, port uint16, protocol uint16, af uint16) error {
	t.Logf("Waiting for socket to close: address: %s, port: %d", addr, port)
	sockListening, err := isSocketListening(t, addr, port, protocol, af)
	if err != nil {
		t.Logf("isSocketListening failed: %s", err)
		return err
	}
	for sockListening {
		sockListening, err = isSocketListening(t, addr, port, protocol, af)
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
