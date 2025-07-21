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

//go:build sudo_tests

package socktrack_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/sensors/config/confmap"
	"github.com/stretchr/testify/assert"

	enterpriseoth "github.com/isovalent/hubble-fgs/pkg/observer/observertesthelper"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/http"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/sockmap"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/sockops"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"
)

const (
	testConfigFile = "/tmp/hubble-tetragon.gotest.yaml"
)

// Run Tetragon without any config as socktrack should load by default.
const udpConfig = `
apiversion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "icmp"
spec:
  parser:
    udp:
      enable: true
`

type sockKey struct {
	SockCookie uint64
}

func (k *sockKey) String() string { return fmt.Sprintf("Cookie: %d", k.SockCookie) }

type sockValue struct {
	Key        processapi.MsgExecveKey
	CreateTime uint64
	Version    uint64
	Protocol   uint8
	Pad        [7]uint8
}

func (v *sockValue) String() string {
	return fmt.Sprintf("Pid: %d, CreateTime: %d, Version: %d, Protocol: %d", v.Key.Pid, v.CreateTime, v.Version, v.Protocol)
}

func TestMain(m *testing.M) {
	bpf.CheckOrMountCgroup2()

	ec := runner.TestSensorsRun(m, "Socktrack")
	os.Exit(ec)
}

func getSocketsForPid(m *ebpf.Map, pid uint32) map[sockKey]sockValue {
	sockets := make(map[sockKey]sockValue)

	var (
		key sockKey
		val sockValue
	)

	iter := m.Iterate()
	for iter.Next(&key, &val) {
		if val.Key.Pid == pid {
			sockets[key] = val
		}
	}
	return sockets
}

func TestAddRemoveSock(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	bpf.CheckOrMountCgroup2()

	if err := observertesthelper.WriteConfigFile(testConfigFile, udpConfig); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}

	base := base.GetInitialSensorTest(t)

	obs, err := enterpriseoth.GetDefaultObserverWithBase(t, ctx, base, testConfigFile, runner.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}
	err = confmap.UpdateTgRuntimeConf(bpf.MapPrefixPath(), os.Getpid())
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}

	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()
	//time.Sleep(time.Minute * 5)
	time.Sleep(time.Second * 1)

	file := filepath.Join(bpf.MapPrefixPath(), "tg_l3_sk")

	m, err := ebpf.LoadPinnedMap(file, nil)
	if err != nil {
		t.Logf("Failed to open map tg_l3_sk: %s", err)
		t.Fail()
	}
	defer m.Close()

	// Get existing sockets for our PID
	preSockets := getSocketsForPid(m, observertesthelper.GetMyPid())

	// Create socket
	syscall.ForkLock.Lock()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	syscall.ForkLock.Unlock()
	if err != nil {
		syscall.Close(fd)
		t.Logf("error: %s", err)
		t.Fail()
	}

	// Get sockets for our PID
	postSockets := getSocketsForPid(m, observertesthelper.GetMyPid())
	// Check that there is one extra socket
	numExtraSockets := 0
	var mySocketKey sockKey
	for c := range postSockets {
		_, ok := preSockets[c]
		if !ok {
			numExtraSockets++
			mySocketKey = c
		}
	}
	assert.Equal(t, 1, numExtraSockets)

	// Check that the lookup works as expected
	var mySocketValue sockValue
	err = m.Lookup(&mySocketKey, &mySocketValue)
	assert.NoError(t, err)

	// Close the socket
	syscall.Close(fd)

	// Check if the socket is still in the map
	err = m.Lookup(&mySocketKey, &mySocketValue)
	if err == nil {
		t.Logf("Socket still in map after close: %s", mySocketValue.String())
		t.Fail()
	}
	if !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Logf("Socket lookup failed with unexpected error: %s", err)
		t.Fail()
	}
}

// LoadTest is conducted in Layer3
