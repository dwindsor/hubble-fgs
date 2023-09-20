package parsertest

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

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
	go dispatch.Run(runCtx, ready)

	// Wait for dispatcher to become ready.
	<-ready

	//
	// Create the ingress and egress connections
	//

	// TODO(JM): Pick a random port. Need to reorganize so we can load TLS and HTTP
	// with right filter.
	srvAddr, err := net.ResolveTCPAddr("tcp4", "127.0.0.88:8888")
	if err != nil {
		return err
	}

	cliAddr, err := net.ResolveTCPAddr("tcp4", "127.0.0.87:0")
	if err != nil {
		return err
	}

	listener, err := net.ListenTCP("tcp4", srvAddr)
	if err != nil {
		return err
	}
	defer listener.Close()

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

	var ingressConn, egressConn *net.TCPConn
	for ingressConn == nil || egressConn == nil {
		select {
		case eoe := <-egressConnOrError:
			if eoe.err != nil {
				return eoe.err
			}
			egressConn = eoe.conn
			defer egressConn.Close()

		case ioe := <-ingressConnOrError:
			if ioe.err != nil {
				return ioe.err
			}
			ingressConn = ioe.conn
			defer ingressConn.Close()
		}
	}

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
