package parsertest

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"text/scanner"
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
	Match(r io.Reader) (int, error)
	Serialize() []byte
}

type StringMatcher string

func (sm StringMatcher) Match(r io.Reader) (int, error) {
	return BytesMatcher([]byte(sm)).Match(r)
}

func (sm StringMatcher) Serialize() []byte {
	return []byte(sm)
}

type BytesMatcher []byte

func (bm BytesMatcher) Match(r io.Reader) (int, error) {
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

func (n WildcardMatcher) Match(r io.Reader) (int, error) {
	m, err := io.CopyN(io.Discard, r, int64(n))
	return int(m), err
}

func (n WildcardMatcher) Serialize() []byte {
	panic("Cannot serialize a wildcard")
}
