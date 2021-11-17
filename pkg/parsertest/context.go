package parsertest

import (
	"fmt"
	"net"
)

type TestContext struct {
	egressConn  *net.TCPConn
	ingressConn *net.TCPConn
	perOpChans  map[int]chan []byte
}

func (ctx *TestContext) Close() {
	ctx.egressConn.Close()
	ctx.ingressConn.Close()
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

func (ctx *TestContext) waitForEvent(op int) (data []byte, eof bool) {
	if ch, ok := ctx.perOpChans[op]; ok {
		data, ok := <-ch
		return data, ok
	} else {
		return nil, false
	}
}
