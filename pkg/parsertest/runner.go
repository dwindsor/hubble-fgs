package parsertest

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func (tc *TestCase) Run(t *testing.T, dispatch *EventDispatcher, timeout time.Duration) error {
	runCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	//
	// Subscribe to all relevant events and start
	// the dispatcher.
	//
	perOpChans := make(map[int]chan []byte)
	for _, step := range tc.Steps {
		switch s := step.(type) {
		case *TestStepEvent:
			perOpChans[s.Op] = nil
		case *TestStepEventDump:
			perOpChans[s.Op] = nil
		}
	}

	for op := range perOpChans {
		sub := dispatch.Subscribe(byte(op))
		perOpChans[op] = sub.Events
	}

	ready := make(chan bool)
	dispatcherErrChan := make(chan error, 1)
	go func() {
		dispatcherErrChan <- dispatch.Run(runCtx, ready)
	}()

	// Wait for dispatcher to become ready.
	<-ready

	//
	// Create the ingress and egress connections
	//

	srvAddr, err := net.ResolveTCPAddr("tcp4", "127.0.0.88:8888")
	if err != nil {
		return err
	}

	// TODO(JM): Client address needs to be unique for each test case.
	// Consider having a matcher that matches on the server and client
	// addresses.
	cliAddr, err := net.ResolveTCPAddr("tcp4", "127.0.0.87:0")
	if err != nil {
		return err
	}

	l, err := net.ListenTCP("tcp4", srvAddr)
	if err != nil {
		return err
	}
	defer l.Close()

	// Concurrently connect and accept. This is a bit funny as we want
	// to fail right away if either of them fail.

	type ConnOrError struct {
		conn *net.TCPConn
		err  error
	}
	egressConnOrError := make(chan ConnOrError)
	go func() {
		conn, err := net.DialTCP("tcp4", cliAddr, srvAddr)
		if err != nil {
			fmt.Printf("DialTCP fail: %s\n", err)
		}
		egressConnOrError <- ConnOrError{conn, err}
	}()

	ingressConnOrError := make(chan ConnOrError)
	go func() {
		conn, err := l.AcceptTCP()
		ingressConnOrError <- ConnOrError{conn, err}
	}()

	var ingressConn, egressConn *net.TCPConn
	for ingressConn == nil || egressConn == nil {
		select {
		case eoe := <-egressConnOrError:
			if eoe.err != nil {
				return eoe.err
			}
			egressConn = eoe.conn
			defer egressConn.Close()
			go io.Copy(io.Discard, egressConn)

		case ioe := <-ingressConnOrError:
			if ioe.err != nil {
				return ioe.err
			}
			ingressConn = ioe.conn
			defer ingressConn.Close()
			go io.Copy(io.Discard, ingressConn)
		}
	}

	//
	// Init the context and start the event dispatcher
	//

	testCtx := &TestContext{
		perOpChans:  perOpChans,
		egressConn:  egressConn,
		ingressConn: ingressConn,
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
				return fmt.Errorf("test failed at step %d/%d:\n%w", i+1, nsteps, err)
			}
		}
	}

	// Final wait for the dispatcher to finish.
	cancel()
	return <-dispatcherErrChan
}
