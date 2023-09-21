package parsertest

import (
	"fmt"
	"net"
)

type FakeListener struct{}

func (listener *FakeListener) Accept() (net.Conn, error) {
	return nil, fmt.Errorf("unimplemented")
}

func (listener *FakeListener) Addr() net.Addr {
	return nil
}

func (listener *FakeListener) Close() error {
	return nil
}
