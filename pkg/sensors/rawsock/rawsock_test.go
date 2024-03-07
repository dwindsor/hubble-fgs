//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//

package rawsock_test

import (
	"context"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/matchers/durationmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/sensors"
	enterpriseoth "github.com/isovalent/hubble-fgs/pkg/observer/observertesthelper"
	"github.com/stretchr/testify/assert"

	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/http"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/layer3"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/sockmap"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/sockops"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/udp"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"

	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
)

const (
	testConfigFile = "/tmp/hubble-tetragon.gotest.yaml"
)

func TestMain(m *testing.M) {
	ec := runner.TestSensorsRun(m, "SensorIcmp")
	os.Exit(ec)
}

const rawsockConfigWithCloseEvents = `
apiversion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "rawsock"
spec:
  parser:
    rawsock:
      enable: true
      reportClose: true
`

func TestLoadRawsockSensor(t *testing.T) {
	if v := "5.4.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}

	bpf.CheckOrMountCgroup2()

	if err := observertesthelper.WriteConfigFile(testConfigFile, rawsockConfigWithCloseEvents); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}

	sens, err := observertesthelper.GetDefaultSensorsWithFile(t, testConfigFile, runner.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}

	sensorProgs := []tus.SensorProg{
		0: tus.SensorProg{Name: "tg_rawsock_sk_init", Type: ebpf.Kprobe},
		1: tus.SensorProg{Name: "tg_rawsockv6_init_sk", Type: ebpf.Kprobe},
		2: tus.SensorProg{Name: "tg_raw_packet_reg_prot_hook", Type: ebpf.Kprobe},
		3: tus.SensorProg{Name: "tg_rawsock_sk_free", Type: ebpf.Kprobe},
	}

	sensorMaps := []tus.SensorMap{
		// all
		tus.SensorMap{Name: "tg_socket_map", Progs: []uint{0, 1, 2, 3}},

		// all
		tus.SensorMap{Name: "tg_socket_map_stats", Progs: []uint{0, 1, 2, 3}},

		// all
		tus.SensorMap{Name: "tcpmon_map", Progs: []uint{0, 1, 2, 3}},

		// just init
		tus.SensorMap{Name: "execve_map", Progs: []uint{0, 1, 2}},
	}

	tus.CheckSensorLoad(sens, sensorMaps, sensorProgs, t)

	sensors.UnloadAll()
}

// NB(kkourt): Function(t *testing.T, ctx context.Context) is the reasonable
// thing to do here even if revive complains.
//
//revive:disable:context-as-argument
func getRawsockObserver(t *testing.T, ctx context.Context) *observer.Observer {
	if err := observertesthelper.WriteConfigFile(testConfigFile, rawsockConfigWithCloseEvents); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}

	base := base.GetInitialSensor()
	obs, err := enterpriseoth.GetDefaultObserverWithBase(t, ctx, base, testConfigFile, runner.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}
	return obs
}

func testRawsockCreateClose(t *testing.T, ty int) {
	if v := "5.4.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessRawsockCreateChecker("rawsockCreate").
			WithProcess(selfChecker),
		ec.NewProcessRawsockCloseChecker("rawsockClose").
			WithProcess(selfChecker).
			WithDuration(durationmatcher.Between(&durationmatcher.Duration{Duration: time.Duration(1 * time.Second)},
				&durationmatcher.Duration{Duration: time.Duration(20 * time.Second)})),
	)

	obs := getRawsockObserver(t, ctx)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()

	// syscall.Socket needs a ForkLock. See https://go.dev/src/syscall/exec_unix.go
	syscall.ForkLock.Lock()
	var fd int
	var err error

	switch ty {
	case 1:
		fd, err = syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_LOOP)
	case 2:
		fd, err = syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, syscall.ETH_P_IP)
	case 3:
		fd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_UDP)
	case 4:
		fd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	case 5:
		fd, err = syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_ALL)
	case 6:
		fd, err = syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, syscall.ETH_P_ALL)
	}
	assert.NoError(t, err)
	time.Sleep(1000 * time.Millisecond)

	syscall.Close(fd)
	syscall.ForkLock.Unlock()

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestRawsockCreateClose1(t *testing.T) {
	testRawsockCreateClose(t, 1)
}

func TestRawsockCreateClose2(t *testing.T) {
	testRawsockCreateClose(t, 2)
}

func TestRawsockCreateClose3(t *testing.T) {
	testRawsockCreateClose(t, 3)
}

func TestRawsockCreateClose4(t *testing.T) {
	testRawsockCreateClose(t, 4)
}

func TestRawsockCreateClose5(t *testing.T) {
	testRawsockCreateClose(t, 5)
}

func TestRawsockCreateClose6(t *testing.T) {
	testRawsockCreateClose(t, 6)
}
