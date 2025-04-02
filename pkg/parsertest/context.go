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

package parsertest

import (
	"fmt"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type TestContext struct {
	egressConn  net.Conn
	ingressConn net.Conn
	listener    net.Listener
	perOpChans  map[int]chan []byte
	t           *testing.T
}

func (ctx *TestContext) emitEgress(pkt []byte) error {
	ctx.egressConn.SetWriteDeadline(time.Now().Add(TEST_TIMEOUT))
	var n int
	var err error
	if udpConn, ok := ctx.egressConn.(*net.UDPConn); ok {
		n, err = udpConn.WriteTo(pkt, ctx.ingressConn.LocalAddr())
	} else {
		n, err = ctx.egressConn.Write(pkt)
	}
	if err != nil {
		return err
	}
	if n != len(pkt) {
		return fmt.Errorf("write failed to write all bytes (%d < %d)",
			n, len(pkt))
	}

	ctx.ingressConn.SetReadDeadline(time.Now().Add(TEST_TIMEOUT))
	b := make([]byte, n)
	n, err = ctx.ingressConn.Read(b)
	if err != nil {
		return err
	}
	if n != len(pkt) {
		return fmt.Errorf("read failed to read all bytes (%d < %d)",
			n, len(pkt))
	}

	if !assert.Equal(ctx.t, pkt, b) {
		return fmt.Errorf("bytes received not equal to bytes sent")
	}

	return nil
}

func (ctx *TestContext) emitIngress(pkt []byte) error {
	ctx.ingressConn.SetWriteDeadline(time.Now().Add(TEST_TIMEOUT))
	var n int
	var err error
	if udpConn, ok := ctx.ingressConn.(*net.UDPConn); ok {
		n, err = udpConn.WriteTo(pkt, ctx.egressConn.LocalAddr())
	} else {
		n, err = ctx.ingressConn.Write(pkt)
	}
	if err != nil {
		return err
	}
	if n != len(pkt) {
		return fmt.Errorf("write failed to write all bytes (%d < %d)",
			n, len(pkt))
	}

	ctx.egressConn.SetReadDeadline(time.Now().Add(TEST_TIMEOUT))
	b := make([]byte, n)
	n, err = ctx.egressConn.Read(b)
	if err != nil {
		return err
	}
	if n != len(pkt) {
		return fmt.Errorf("read failed to read all bytes (%d < %d)",
			n, len(pkt))
	}

	if !assert.Equal(ctx.t, pkt, b) {
		return fmt.Errorf("bytes received not equal to bytes sent")
	}

	return nil
}

func (ctx *TestContext) closeConns() error {
	err1 := ctx.egressConn.Close()
	err2 := ctx.ingressConn.Close()
	err3 := ctx.listener.Close()
	if err1 != nil {
		return err1
	}
	if err2 != nil {
		return err2
	}
	if err3 != nil {
		return err3
	}
	return nil
}

func (ctx *TestContext) waitForEvent(op int) (data []byte, eof bool) {
	if ch, ok := ctx.perOpChans[op]; ok {
		data, eof := <-ch
		return data, eof
	}
	panic(fmt.Sprintf("Impossible: Not subscribed for op %d", op))
}

func (ctx *TestContext) waitForEvents(ops []int) (data []byte, eof bool) {
	seen := make(map[int]struct{})
	var cases []reflect.SelectCase
	for _, op := range ops {
		// Don't add an op twice
		if _, ok := seen[op]; ok {
			continue
		}
		seen[op] = struct{}{}
		if ch, ok := ctx.perOpChans[op]; ok {
			cases = append(cases, reflect.SelectCase{
				Dir:  reflect.SelectRecv,
				Chan: reflect.ValueOf(ch),
			})
		} else {
			panic(fmt.Sprintf("Impossible: Not subscribed for op %d", op))
		}
	}
	_, recv, ok := reflect.Select(cases)
	if !ok {
		return nil, false
	}
	return recv.Interface().([]byte), true
}
