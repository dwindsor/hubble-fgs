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
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"text/scanner"
	"unsafe"

	"github.com/yalue/native_endian"

	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
)

// AnnMatcher is an annotated matcher that includes line
// number information.
type AnnMatcher struct {
	Matcher
	Position scanner.Position
}

// Matcher provides a method for scanning through an io.Reader and
// matching on the data.
type Matcher interface {
	Match(ctx *TestContext, r io.Reader) (int, error)
	Serialize() []byte
}

type StringMatcher string

func (sm StringMatcher) Match(ctx *TestContext, r io.Reader) (int, error) {
	return BytesMatcher([]byte(sm)).Match(ctx, r)
}

func (sm StringMatcher) Serialize() []byte {
	return []byte(sm)
}

type BytesMatcher []byte

func (bm BytesMatcher) String() string {
	s := "$ "
	for i, b := range bm {
		s += fmt.Sprintf("%02x", b)
		if i != len(bm)-1 {
			s += " "
		}
	}
	return s
}

func (bm BytesMatcher) Match(_ *TestContext, r io.Reader) (int, error) {
	buf := make([]byte, len(bm))
	n, err := r.Read(buf)
	if err != nil {
		return 0, fmt.Errorf("failed to read %d bytes: %w", len(bm), err)
	}
	if n != len(bm) {
		return 0, fmt.Errorf("EOF, expected %d, but only got %d bytes", n, len(bm))
	}
	if !bytes.Equal(bm, buf) {
		return 0, fmt.Errorf("mismatch, expected %s, got %s", bm, BytesMatcher(buf))
	}
	return len(bm), nil
}

func (bm BytesMatcher) Serialize() []byte {
	return bm
}

type WildcardMatcher int

func (n WildcardMatcher) Match(_ *TestContext, r io.Reader) (int, error) {
	m, err := io.CopyN(io.Discard, r, int64(n))
	if err != nil {
		err = fmt.Errorf("wildcard match failed, read %d bytes, expected %d bytes: %w", m, n, err)
	}
	return int(m), err
}

func (n WildcardMatcher) Serialize() []byte {
	panic("Cannot serialize a wildcard")
}

type NonZeroMatcher int

func (n NonZeroMatcher) Match(_ *TestContext, r io.Reader) (int, error) {
	zeroes := make([]byte, n)
	buf := make([]byte, n)
	m, err := r.Read(buf)
	if m != int(n) {
		err = fmt.Errorf("non-zero match failed, read %d bytes, expected %d bytes: %w", m, n, err)
	}
	if bytes.Equal(zeroes, buf) {
		err = fmt.Errorf("mismatch, expected %d non-zero bytes, but found all zeroes", n)
	}
	return int(m), err
}

func (n NonZeroMatcher) Serialize() []byte {
	panic("Cannot serialize a non-zero matcher")
}

const (
	CMK_IP_RAW = iota
	CMK_IP_STRING
	CMK_PORT_NET
	CMK_PORT_HOST
)

type ConnAddrMatcher struct {
	kind     int
	isClient bool
}

func (cam ConnAddrMatcher) Match(ctx *TestContext, r io.Reader) (int, error) {
	var addr net.Addr
	if cam.isClient {
		addr = ctx.egressConn.LocalAddr()
	} else {
		addr = ctx.ingressConn.LocalAddr()
	}
	host, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return 0, err
	}
	expectedIP := net.ParseIP(host)
	expectedPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return 0, err
	}
	switch cam.kind {
	case CMK_IP_RAW:
		var actualIP net.IP = make([]byte, 4)
		n, err := r.Read(actualIP)
		if err != nil {
			return 0, err
		}
		if !expectedIP.Equal(actualIP) {
			return 0, fmt.Errorf("address mismatch, expected %s, got %s", expectedIP, actualIP)
		}
		return n, nil

	case CMK_IP_STRING:
		actualIP := make([]byte, len(expectedIP.String()))
		n, err := r.Read(actualIP)
		if err != nil {
			return 0, err
		}

		if !bytes.Equal(actualIP, []byte(expectedIP.String())) {
			return 0, fmt.Errorf("address mismatch, expected %s, got %s",
				expectedIP, string(actualIP))
		}
		return n, nil

	case CMK_PORT_NET, CMK_PORT_HOST:
		bytes := make([]byte, 2)
		n, err := r.Read(bytes)
		if err != nil {
			return 0, err
		}
		var actualPort uint16
		if cam.kind == CMK_PORT_NET {
			actualPort = binary.BigEndian.Uint16(bytes)
		} else {
			actualPort = native_endian.NativeEndian().Uint16(bytes)
		}
		if uint64(actualPort) != expectedPort {
			return 0, fmt.Errorf("port mismatch, expected %d, got %d", expectedPort, actualPort)
		}
		return n, nil
	default:
		panic("unimplemented ConnAddrMatcher")
	}
}

func (cam ConnAddrMatcher) Serialize() []byte {
	panic("Cannot serialize a connection address matcher")
}

type TupleMatcherIP struct {
	IsCli bool
	IsSrv bool
	Addr  netip.AddrPort
}

// Matches the full tuple
type TupleMatcher struct {
	Source TupleMatcherIP
	Dest   TupleMatcherIP
	// TODO: Add IPv6 flag to support IPv6 addrs
}

func addrToIpPort(addr net.Addr) (net.IP, uint16, error) {
	addrStr, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil, 0, err
	}

	ip := net.ParseIP(addrStr)
	if ip == nil {
		return nil, 0, fmt.Errorf("failed to parse IP '%s'", addrStr)
	}

	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, 0, err
	}

	return ip, uint16(port), nil
}

func convertNetipAddrPort(addr netip.AddrPort) (net.IP, uint16) {
	return net.IP(addr.Addr().AsSlice()), addr.Port()

}

func (tm TupleMatcher) Match(ctx *TestContext, r io.Reader) (int, error) {
	var tuple networkapi.MsgIPTuple
	n := 0
	if err := binary.Read(r, native_endian.NativeEndian(), &tuple); err != nil {
		return n, err
	}
	n = int(unsafe.Sizeof(tuple))

	var err error
	var saddr, daddr net.IP
	var sport, dport uint16
	if tm.Source.IsCli {
		saddr, sport, err = addrToIpPort(ctx.egressConn.LocalAddr())
		if err != nil {
			return n, err
		}
	} else if tm.Source.IsSrv {
		saddr, sport, err = addrToIpPort(ctx.ingressConn.LocalAddr())
		if err != nil {
			return n, err
		}
	} else {
		saddr, sport = convertNetipAddrPort(tm.Source.Addr)
	}
	if tm.Dest.IsCli {
		daddr, dport, err = addrToIpPort(ctx.egressConn.LocalAddr())
		if err != nil {
			return n, err
		}
	} else if tm.Dest.IsSrv {
		daddr, dport, err = addrToIpPort(ctx.ingressConn.LocalAddr())
		if err != nil {
			return n, err
		}
	} else {
		daddr, dport = convertNetipAddrPort(tm.Dest.Addr)
	}

	actualIP := net.IP(make([]byte, 4))
	binary.LittleEndian.PutUint32(actualIP, uint32(tuple.SAddr[0]))
	if !saddr.Equal(actualIP) {
		return n, fmt.Errorf("src address mismatch, expected %s, got %s", saddr, actualIP)
	}

	// Match sport
	if tuple.SPort != sport {
		return n, fmt.Errorf("src port mismatch, expected %d, got %d", sport, tuple.SPort)
	}

	// Match daddr
	actualIP = net.IP(make([]byte, 4))
	binary.LittleEndian.PutUint32(actualIP, uint32(tuple.DAddr[0]))
	if !daddr.Equal(actualIP) {
		return n, fmt.Errorf("dst address mismatch, expected %s, got %s", daddr, actualIP)
	}

	// Match dport
	if tuple.DPort != dport {
		return n, fmt.Errorf("dst port mismatch, expected %d, got %d", dport, tuple.DPort)
	}

	// IPv6 is unsupported for now
	if tuple.IPv6 != 0 {
		return n, fmt.Errorf("expected IPv6=0, got %d", tuple.IPv6)
	}

	return n, nil
}

func (tm TupleMatcher) Serialize() []byte {
	panic("Cannot serialize a tuple matcher")
}
