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
	"flag"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"testing"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/sensors"
	tusee "github.com/isovalent/hubble-fgs/pkg/testutils/sensors"

	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/testutil"
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
	if v := "4.19.0"; !kernels.MinKernelVersion(v) && os.Getenv("KVM_CI") != "" {
		fmt.Fprintf(os.Stderr, "Minimum kernel version (%v) for Layer3 tests in KVM CI not met, skipping", v)
		return
	}
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
	os.Exit(ec)
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
const layer3Config = `
apiversion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "layer3"
spec:
  parser:
    tcp:
      enable: true
      statsInterval: 20
      histogram:
        enable: true
        min: 0
        max: 4000
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
const layer3IcmpRawConfig = layer3Config + `
    icmp:
      enable: true
    rawsock:
      enable: true
      reportClose: true
`

func TestLoadLayer3Sensor(t *testing.T) {
	var l3Config string
	if !kernels.MinKernelVersion("5.4.0") {
		logger.GetLogger().Info("Disabling ICMP as it requires kernel v5.4 or later")
		l3Config = layer3Config
	} else {
		l3Config = layer3IcmpRawConfig
	}
	if err := observertesthelper.WriteConfigFile(testConfigFile, l3Config); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}

	b := base.GetInitialSensor()
	sens, err := observertesthelper.GetDefaultSensorsWithBase(t, b, testConfigFile, runner.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultSensorsWithBase error: %s", err)
	}

	sensorProgs, sensorMaps := testutil.ProgsAndMaps(true, true, true, true)

	tusee.CheckSensorLoad(sens, sensorMaps, sensorProgs, t)

	sensi := make([]sensors.SensorIface, 0, len(sens))
	for _, s := range sens {
		sensi = append(sensi, s)
	}
	sensors.UnloadSensors(sensi)
}
