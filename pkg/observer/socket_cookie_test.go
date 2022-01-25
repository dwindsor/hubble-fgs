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
package observer

import (
	"context"
	"fmt"
	"sync"
	"syscall"
	"testing"

	ec "github.com/isovalent/hubble-fgs/pkg/eventchecker"

	"golang.org/x/sys/unix"
)

func socketCookieTest(t *testing.T) (ec.MultiResponseChecker, error) {

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

	checks := []ec.ResponseChecker{}
	addCheck := func(c ec.ResponseChecker) {
		checks = append(checks, c)
	}

	getFDAndCookie := func() (int, uint64, error) {
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
		if err != nil {
			return -1, 0, fmt.Errorf("socket failed: %w", err)
		}
		cookie, err := unix.GetsockoptUint64(fd, syscall.SOL_SOCKET, unix.SO_COOKIE)
		if err != nil {
			return -1, 0, fmt.Errorf("getsockopt failed: %w", err)
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
	addCheck(ec.NewListenEventChecker().HasCookie(lCookie).End())

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
	addCheck(ec.NewConnectEventChecker().HasCookie(cCookie).End())

	aFD, _, err = unix.Accept(lFD)
	if err != nil {
		return nil, fmt.Errorf("accept failed: %w", err)
	}
	// cannot set cookie for accept from user-space
	addCheck(ec.NewAcceptEventChecker().End())

	unix.Close(aFD)
	aFD = -1
	addCheck(ec.NewCloseEventChecker().End())

	unix.Close(cFD)
	cFD = -1
	addCheck(ec.NewCloseEventChecker().HasCookie(cCookie).End())

	unix.Close(lFD)
	lFD = -1
	addCheck(ec.NewCloseEventChecker().HasCookie(lCookie).End())

	checker := ec.NewUnorderedMultiResponseChecker(checks...)
	return checker, nil
}

func TestSocketCookie(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()
	var exitWG, execWG sync.WaitGroup

	obs, err := getDefaultObserverWithWatchers(t, withPretty(), withLib(fgsLib))
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}
	LoopEvents(t, &exitWG, &execWG, obs, ctx)
	execWG.Wait()
	checker, err := socketCookieTest(t)
	if err != nil {
		t.Fatalf("socketCookieTest failed: %s", err)
	}
	exitWG.Wait()

	if err := JsonTestCheck(t, nil, checker); err != nil {
		t.Logf("error: %s", err)
		t.Fail()
	}
	TestDone(t, obs)
}
