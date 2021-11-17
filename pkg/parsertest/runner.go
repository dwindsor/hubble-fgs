package parsertest

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func (tc *TestCase) Run(t *testing.T, dispatch *EventDispatcher, timeout time.Duration) error {
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
	done := make(chan bool)
	errs := make(chan error)

	go func() {
		// Wait for dispatcher to become ready.
		<-ready

		//
		// Create the ingress and egress connections
		//

		srvAddr, err := net.ResolveTCPAddr("tcp4", "127.0.0.88:8888")
		if err != nil {
			panic(err)
		}

		// TODO: force sport? reuse issues though.
		cliAddr, err := net.ResolveTCPAddr("tcp4", "127.0.0.87:0")
		if err != nil {
			panic(err)
		}

		egressConn := make(chan *net.TCPConn)
		ingressConn := make(chan *net.TCPConn)
		ingressReady := make(chan bool)
		go func() {
			l, err := net.ListenTCP("tcp4", srvAddr)
			if err != nil {
				panic(err)
			}
			ingressReady <- true
			conn, err := l.AcceptTCP()
			if err != nil {
				panic(err)
			}
			conn.SetNoDelay(true)
			go io.Copy(io.Discard, conn)
			ingressConn <- conn
		}()
		go func() {
			<-ingressReady
			conn, err := net.DialTCP("tcp4", cliAddr, srvAddr)
			if err != nil {
				panic(err)
			}
			conn.SetNoDelay(true)
			go io.Copy(io.Discard, conn)
			egressConn <- conn
		}()

		//
		// Init the context and start the event dispatcher
		//

		ctx := &TestContext{
			perOpChans:  perOpChans,
			egressConn:  <-egressConn,
			ingressConn: <-ingressConn,
			t:           t,
		}
		defer ctx.Close()

		//
		// Step through the test case
		//
		var testErr error = nil
		for _, step := range tc.Steps {
			if err := step.Exec(ctx); err != nil {
				testErr = fmt.Errorf("test failed: %w", err)
				break
			}
		}
		done <- true
		errs <- testErr
	}()

	dispatch.Run(timeout, ready, done)
	return <-errs
}
