//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package layer3

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/sensors"

	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"

	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"

	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
)

var (
	tcpClient           = false
	tcpServer           = false
	tcpIouServer        = false
	tcpIouClient        = false
	udpWatermarksClient = false
	udpLayer7Client     = false
	udpServer           = false
	udpIouServer        = false
)

const (
	testConfigFile  = "/tmp/hubble-tetragon.gotest.yaml"
	alpineCurlImage = "quay.io/cilium/alpine-curl:v1.6.0"
)

func init() {
	flag.BoolVar(&tcpClient, "tcpClient", false, "internal")
	flag.BoolVar(&tcpServer, "tcpServer", false, "internal")
	flag.BoolVar(&tcpIouServer, "tcpIouServer", false, "internal")
	flag.BoolVar(&tcpIouClient, "tcpIouClient", false, "internal")

	flag.BoolVar(&udpWatermarksClient, "udpWatermarksClient", false, "internal")
	flag.BoolVar(&udpLayer7Client, "udpLayer7Client", false, "internal")
	flag.BoolVar(&udpServer, "udpServer", false, "internal")
	flag.BoolVar(&udpIouServer, "udpIouServer", false, "internal")
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
	if tcpIouServer {
		runTcpIouServer()
		os.Exit(0)
	}
	if tcpClient {
		runTcpClient()
		os.Exit(0)
	}
	if tcpIouClient {
		runTcpIouClient()
		os.Exit(0)
	}
	if udpServer {
		runUdpServer()
		os.Exit(0)
	}
	if udpIouServer {
		runUdpIouServer()
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

func TestLoadLayer3Sensor(t *testing.T) {
	if err := observertesthelper.WriteConfigFile(testConfigFile, tcpBasicConfig); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}

	sens, err := observertesthelper.GetDefaultSensorsWithFile(t, testConfigFile, runner.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultSensorsWithFile error: %s", err)
	}

	sensorProgs, sensorMaps := ProgsAndMaps(false)

	if err := observertesthelper.WriteConfigFile(testConfigFile, udpBasicConfig); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}

	tus.CheckSensorLoad(sens, sensorMaps, sensorProgs, t)

	sensors.UnloadSensors(sens)
}
