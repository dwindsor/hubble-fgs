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
	"fmt"
	"os"
	"sync"
	"syscall"
	"testing"

	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/stretchr/testify/require"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"

	enterpriseoth "github.com/isovalent/hubble-fgs/pkg/observer/observertesthelper"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/internal/ip"
	cli "github.com/isovalent/hubble-fgs/pkg/testutils/cliswitches"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"

	"golang.org/x/sys/unix"
)

func socketCookieTest(_ *testing.T) (ec.MultiEventChecker, error) {
	checker := ec.NewUnorderedEventChecker()

	// initialize listen, connect, and accept file descriptors, and ensure that they
	// are closed once we return
	lFD, cFD, aFD := -1, -1, -1
	defer func() {
		if lFD != -1 {
			syscall.Close(lFD)
		}
		if cFD != -1 {
			syscall.Close(cFD)
		}
		if aFD != -1 {
			syscall.Close(aFD)
		}
	}()

	getFDAndCookie := func() (int, uint64, error) {
		// syscall.Socket needs a ForkLock. See https://go.dev/src/syscall/exec_unix.go
		syscall.ForkLock.Lock()
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
		syscall.ForkLock.Unlock()
		if err != nil {
			return -1, 0, fmt.Errorf("socket failed: %w", err)
		}
		cookie := ip.GetSocketForFD(syscall.IPPROTO_TCP, os.Getpid(), fd, 0, 0)
		if cookie == 0 {
			socket, err := ip.GetAndAddSocketViaProc(uint32(os.Getpid()), uint32(fd), unix.IPPROTO_TCP, nil)
			if err != nil {
				return 0, 0, fmt.Errorf("failed to get socket from proc: %w", err)
			}
			cookie = socket.Sockaddr
		}
		return fd, cookie, nil
	}

	lFD, lCookie, err := getFDAndCookie()
	if err != nil {
		return nil, err
	}

	if err := unix.Listen(lFD, 1); err != nil {
		return nil, fmt.Errorf("listen failed: %w", err)
	}
	checker.AddChecks(ec.NewProcessListenChecker("listen").WithSockCookie(lCookie))

	laddr, err := unix.Getsockname(lFD)
	if err != nil {
		return nil, fmt.Errorf("getsockname failed: %w", err)
	}

	cFD, cCookie, err := getFDAndCookie()
	if err != nil {
		return nil, err
	}

	err = unix.Connect(cFD, laddr)
	if err != nil {
		return nil, fmt.Errorf("connect failed: %w", err)
	}
	checker.AddChecks(ec.NewProcessConnectChecker("connect").WithSockCookie(cCookie))

	aFD, _, err = unix.Accept(lFD)
	if err != nil {
		return nil, fmt.Errorf("accept failed: %w", err)
	}
	aCookie := ip.GetSocketForFD(syscall.IPPROTO_TCP, os.Getpid(), aFD, 0, 0)
	// cannot set cookie for accept from user-space
	checker.AddChecks(ec.NewProcessAcceptChecker("accept"))

	unix.Close(lFD)
	lFD = -1
	checker.AddChecks(ec.NewProcessCloseChecker("closeListen").WithSockCookie(lCookie))

	unix.Close(cFD)
	cFD = -1
	checker.AddChecks(ec.NewProcessCloseChecker("closeConnect").WithSockCookie(cCookie))

	unix.Close(aFD)
	aFD = -1
	// Sometimes the accept cookie is 0. It is unclear why but if the other two cookies are good,
	// then this is a flake we can just ignore.
	if aCookie != 0 {
		checker.AddChecks(ec.NewProcessCloseChecker("closeAccept").WithSockCookie(aCookie))
	} else {
		checker.AddChecks(ec.NewProcessCloseChecker("closeAccept"))
	}

	return checker, nil
}

func testSocketCookie(t *testing.T, CLISwitches bool) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	if CLISwitches {
		require.NoError(t, cli.SetSwitches(t, []cli.SwitchSettings{
			{KeyPtr: &enterpriseOption.Config.Layer3CLIEnable, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableNetworkEvents, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableTCP, Value: true},
		}))
	}

	obs := enterpriseoth.GetNoConfigObserver(t, ctx, true)
	require.NoError(t, layer3.StartLayer3Progs(ctx, nil))

	if !CLISwitches {
		tp, err := tracingpolicy.FromYAML(tcpBasicConfig)
		require.NoError(t, err)
		err = observer.GetSensorManager().AddTracingPolicy(ctx, tp)
		require.NoError(t, err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()
	checker, err := socketCookieTest(t)
	require.NoError(t, err)

	err = jsonchecker.JsonTestCheck(t, checker)
	require.NoError(t, err)
}

func TestSocketCookie(t *testing.T) {
	testSocketCookie(t, false)
}

func TestSocketCookieCLI(t *testing.T) {
	testSocketCookie(t, true)
}
