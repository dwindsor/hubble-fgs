// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package parsertest

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

func setupTCPPeers(t *testing.T, ingressPort, egressPort int) (ingressConn, egressConn *net.TCPConn, listener *net.TCPListener, err error) {
	srvAddr, err := net.ResolveTCPAddr("tcp4", fmt.Sprintf("127.0.0.88:%d", ingressPort))
	if err != nil {
		return nil, nil, nil, err
	}

	cliAddr, err := net.ResolveTCPAddr("tcp4", fmt.Sprintf("127.0.0.87:%d", egressPort))
	if err != nil {
		return nil, nil, nil, err
	}

	listener, err = net.ListenTCP("tcp4", srvAddr)
	if err != nil {
		return nil, nil, nil, err
	}

	// Concurrently connect and accept. This is a bit funny as we want
	// to fail right away if either of them fail.

	type ConnOrError struct {
		conn *net.TCPConn
		err  error
	}
	egressConnOrError := make(chan ConnOrError)
	go func() {
		conn, err := net.DialTCP("tcp4", cliAddr, listener.Addr().(*net.TCPAddr))
		if err != nil {
			fmt.Printf("DialTCP fail: %s\n", err)
		}
		egressConnOrError <- ConnOrError{conn, err}
	}()

	ingressConnOrError := make(chan ConnOrError)
	go func() {
		conn, err := listener.AcceptTCP()
		ingressConnOrError <- ConnOrError{conn, err}
	}()

	for ingressConn == nil || egressConn == nil {
		select {
		case eoe := <-egressConnOrError:
			if eoe.err != nil {
				listener.Close()
				return nil, nil, nil, eoe.err
			}
			egressConn = eoe.conn

		case ioe := <-ingressConnOrError:
			if ioe.err != nil {
				listener.Close()
				egressConn.Close()
				return nil, nil, nil, ioe.err
			}
			ingressConn = ioe.conn
		}
	}

	t.Logf("Started TCP peers ingress=%v egress=%v", ingressConn.LocalAddr(), egressConn.LocalAddr())

	return ingressConn, egressConn, listener, nil
}

func setupUDPPeers(t *testing.T, ingressPort, egressPort int) (ingressConn, egressConn *net.UDPConn, err error) {
	srvAddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("127.0.0.88:%d", ingressPort))
	if err != nil {
		return nil, nil, err
	}

	cliAddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("127.0.0.87:%d", egressPort))
	if err != nil {
		return nil, nil, err
	}

	egressConn, err = net.ListenUDP("udp4", cliAddr)
	if err != nil {
		return nil, nil, err
	}

	ingressConn, err = net.ListenUDP("udp4", srvAddr)
	if err != nil {
		egressConn.Close()
		return nil, nil, err
	}

	t.Logf("Started UDP peers ingress=%v egress=%v", ingressConn.LocalAddr(), egressConn.LocalAddr())

	return ingressConn, egressConn, nil
}

func (tc *TestCase) Run(t *testing.T, timeout time.Duration) error {
	dispatch, err := NewEventDispatcher()
	if err != nil {
		return err
	}

	runCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	dispatcherErrChan := make(chan error, 1)
	go func() {
		<-runCtx.Done()
		dispatcherErrChan <- dispatch.Close()
	}()

	//
	// Subscribe to all relevant events and start
	// the dispatcher.
	//
	perOpChans := make(map[int]chan []byte)
	for _, step := range tc.Steps {
		switch s := step.(type) {
		case *TestStepEvent:
			perOpChans[s.Op] = nil
		case *TestStepEvents:
			for _, op := range s.Ops {
				perOpChans[op] = nil
			}
		case *TestStepEventDump:
			perOpChans[s.Op] = nil
		}
	}

	for op := range perOpChans {
		sub := dispatch.Subscribe(byte(op))
		perOpChans[op] = sub.Events
	}

	ready := make(chan bool)
	go dispatch.Run(runCtx, ready)

	// Wait for dispatcher to become ready.
	<-ready

	//
	// Create the ingress and egress connections
	//

	var ingressConn, egressConn net.Conn
	var listener net.Listener

	if tc.IsTcp() {
		ingressConn, egressConn, listener, err = setupTCPPeers(t, tc.IngressPort, tc.EgressPort)
		if err != nil {
			return err
		}
	}
	if tc.IsUdp() {
		ingressConn, egressConn, err = setupUDPPeers(t, tc.IngressPort, tc.EgressPort)
		if err != nil {
			return err
		}
		listener = &FakeListener{}
	}
	defer egressConn.Close()
	defer ingressConn.Close()
	defer listener.Close()

	//
	// Init the context and start the event dispatcher
	//

	testCtx := &TestContext{
		perOpChans:  perOpChans,
		egressConn:  egressConn,
		ingressConn: ingressConn,
		listener:    listener,
		t:           t,
	}

	//
	// Step through the test case
	//
	nsteps := len(tc.Steps)
	for i, step := range tc.Steps {
		select {
		case err := <-dispatcherErrChan:
			return err
		default:
			if err := step.Exec(testCtx); err != nil {
				cancel()
				<-dispatcherErrChan
				return fmt.Errorf("test failed at step %d/%d:\n%w", i+1, nsteps, err)
			}
		}
	}

	// Final wait for the dispatcher to finish.
	cancel()
	return <-dispatcherErrChan
}
