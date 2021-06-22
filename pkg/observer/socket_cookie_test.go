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

	"golang.org/x/sys/unix"
)

func socketCookieTest(t *testing.T) (eventChecker, error) {

	var lFD, cFD int = -1, -1
	defer func() {
		if lFD != -1 {
			syscall.Close(lFD)
		}
		if cFD != -1 {
			syscall.Close(cFD)
		}
	}()
	checks := []eventChecker{}
	addCheck := func(c eventChecker) {
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
	addCheck(newChainEventChecker().isListenEvent().hasCookie(lCookie).match())

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
	addCheck(newChainEventChecker().isConnectEvent().hasCookie(cCookie).match())

	aFD, _, err := unix.Accept(lFD)
	if err != nil {
		return nil, fmt.Errorf("accept failed: %w", err)
	}
	// cannot set cookie for accept from user-space
	addCheck(newChainEventChecker().isAcceptEvent().match())
	unix.Close(aFD)

	cl := newChainEventChecker().isCloseEvent().hasCookie(lCookie).match()
	cc := newChainEventChecker().isCloseEvent().hasCookie(cCookie).match()
	ca := newChainEventChecker().isCloseEvent().match()
	addCheck(newUnorderedListEventChecker(cl, cc, ca))

	return &listEventChecker{
		checkers: checks,
	}, nil
}

func TestSocketCookie(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()
	var exitWG, execWG sync.WaitGroup

	kprobe, err := getDefaultObserverWithWatchers(t, withPretty())
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}
	loopEvents(t, &exitWG, &execWG, kprobe, ctx)
	execWG.Wait()
	checker, err := socketCookieTest(t)
	if err != nil {
		t.Fatalf("socketCookieTest failed: %s", err)
	}
	exitWG.Wait()

	if err := jsonTestCheck(t, nil, checker); err != nil {
		t.Logf("error: %s", err)
		t.Fail()
	}
	testDone(t, kprobe)
}
