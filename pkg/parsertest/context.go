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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type TestContext struct {
	egressConn  *net.TCPConn
	ingressConn *net.TCPConn
	listener    net.Listener
	perOpChans  map[int]chan []byte
	t           *testing.T
}

func (ctx *TestContext) emitEgress(pkt []byte) error {
	ctx.egressConn.SetWriteDeadline(time.Now().Add(testTimeout))
	n, err := ctx.egressConn.Write(pkt)
	if err != nil {
		return err
	}
	if n != len(pkt) {
		return fmt.Errorf("Write failed to write all bytes (%d < %d)",
			n, len(pkt))
	}

	ctx.ingressConn.SetReadDeadline(time.Now().Add(testTimeout))
	b := make([]byte, n)
	n, err = ctx.ingressConn.Read(b)
	if err != nil {
		return err
	}
	if n != len(pkt) {
		return fmt.Errorf("Read failed to read all bytes (%d < %d)",
			n, len(pkt))
	}

	if !assert.Equal(ctx.t, pkt, b) {
		return fmt.Errorf("Bytes received not equal to bytes sent")
	}

	return nil
}

func (ctx *TestContext) emitIngress(pkt []byte) error {
	ctx.ingressConn.SetWriteDeadline(time.Now().Add(testTimeout))
	n, err := ctx.ingressConn.Write(pkt)
	if err != nil {
		return err
	}
	if n != len(pkt) {
		return fmt.Errorf("Write failed to write all bytes (%d < %d)",
			n, len(pkt))
	}

	ctx.egressConn.SetReadDeadline(time.Now().Add(testTimeout))
	b := make([]byte, n)
	n, err = ctx.egressConn.Read(b)
	if err != nil {
		return err
	}
	if n != len(pkt) {
		return fmt.Errorf("Read failed to read all bytes (%d < %d)",
			n, len(pkt))
	}

	if !assert.Equal(ctx.t, pkt, b) {
		return fmt.Errorf("Bytes received not equal to bytes sent")
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
