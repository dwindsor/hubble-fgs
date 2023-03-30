//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package tcp

import (
	"context"
	"fmt"
	"os"
	"sync"
	"syscall"
	"testing"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/isovalent/hubble-fgs/pkg/sensors/ip"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"

	"golang.org/x/sys/unix"
)

func socketCookieTest(t *testing.T) (ec.MultiEventChecker, error) {
	checker := ec.NewUnorderedEventChecker()

	// initialize listen, connect, and accept file descriptors, and ensure that they
	// are closed once we return
	var lFD, cFD, aFD int = -1, -1, -1
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
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, IPPROTO_TCP)
		syscall.ForkLock.Unlock()
		if err != nil {
			return -1, 0, fmt.Errorf("socket failed: %w", err)
		}
		cookie := ip.GetSocketForFD(IPPROTO_TCP, os.Getpid(), fd, 0, 0)
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
	aCookie := ip.GetSocketForFD(IPPROTO_TCP, os.Getpid(), aFD, 0, 0)
	// cannot set cookie for accept from user-space
	checker.AddChecks(ec.NewProcessAcceptChecker("accept"))

	unix.Close(aFD)
	aFD = -1
	checker.AddChecks(ec.NewProcessCloseChecker("closeAccept").WithSockCookie(aCookie))

	unix.Close(cFD)
	cFD = -1
	checker.AddChecks(ec.NewProcessCloseChecker("closeConnect").WithSockCookie(cCookie))

	unix.Close(lFD)
	lFD = -1
	checker.AddChecks(ec.NewProcessCloseChecker("closeListen").WithSockCookie(lCookie))
	return checker, nil
}

func TestSocketCookie(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	if err := observer.WriteConfigFile(testConfigFile, tcpBasicConfig); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}
	obs, err := observer.GetDefaultObserverWithLib(t, ctx, testConfigFile, runner.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()
	checker, err := socketCookieTest(t)
	if err != nil {
		t.Fatalf("socketCookieTest failed: %s", err)
	}

	if err := jsonchecker.JsonTestCheck(t, checker); err != nil {
		t.Logf("error: %s", err)
		t.Fail()
	}
}
