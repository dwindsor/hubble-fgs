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
)

type TestContext struct {
	egressConn  *net.TCPConn
	ingressConn *net.TCPConn
	perOpChans  map[int]chan []byte
	t           *testing.T
}

func (ctx *TestContext) emitEgress(pkt []byte) error {
	n, err := ctx.egressConn.Write(pkt)
	if err != nil {
		return err
	}
	if n != len(pkt) {
		return fmt.Errorf("Write failed to write all bytes (%d < %d)",
			n, len(pkt))
	}
	return nil
}

func (ctx *TestContext) emitIngress(pkt []byte) error {
	n, err := ctx.ingressConn.Write(pkt)
	if err != nil {
		return err
	}
	if n != len(pkt) {
		return fmt.Errorf("Write failed to write all bytes (%d < %d)",
			n, len(pkt))
	}
	return nil
}

func (ctx *TestContext) closeConns() error {
	err := ctx.egressConn.Close()
	if err != nil {
		return err
	}
	err = ctx.ingressConn.Close()
	if err != nil {
		return err
	}
	return nil
}

func (ctx *TestContext) waitForEvent(op int) (data []byte, eof bool) {
	if ch, ok := ctx.perOpChans[op]; ok {
		data, ok := <-ch
		return data, ok
	}
	return nil, false
}
