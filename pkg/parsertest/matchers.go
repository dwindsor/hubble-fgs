package parsertest

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"text/scanner"

	"github.com/yalue/native_endian"
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

func (bm BytesMatcher) Match(_ *TestContext, r io.Reader) (int, error) {
	buf := make([]byte, len(bm))
	n, err := r.Read(buf)
	if err != nil {
		return 0, err
	}
	if n != len(bm) || !bytes.Equal(bm, buf) {
		return 0, fmt.Errorf("mismatch, expected %s, got %s", hex.EncodeToString(bm), hex.EncodeToString(buf))
	}
	return len(bm), nil
}

func (bm BytesMatcher) Serialize() []byte {
	return bm
}

type WildcardMatcher int

func (n WildcardMatcher) Match(_ *TestContext, r io.Reader) (int, error) {
	m, err := io.CopyN(io.Discard, r, int64(n))
	return int(m), err
}

func (n WildcardMatcher) Serialize() []byte {
	panic("Cannot serialize a wildcard")
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

func (_ ConnAddrMatcher) Serialize() []byte {
	panic("Cannot serialize a connection address matcher")
}
