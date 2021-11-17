package parsertest

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"text/scanner"

	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/yalue/native_endian"
)

//
// Parser for the test-case definition language
//

type Parser struct {
	testCase TestCase
	scanner  *scanner.Scanner
}

func ParseTestCase(file string) (*TestCase, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	parser := &Parser{
		scanner: &scanner.Scanner{},
	}
	parser.scanner.Init(f)
	parser.scanner.Filename = file
	parser.scanner.Whitespace ^= 1 << '\n'
	parser.scanner.Mode = scanner.SkipComments | scanner.ScanIdents | scanner.ScanStrings | scanner.ScanRawStrings
	parser.testCase.Name = path.Base(file)

	for {
		err := parser.parseBlock()
		if err != nil {
			return nil, fmt.Errorf("%s:%d:%d: error: %w", file, parser.scanner.Line, parser.scanner.Column, err)
		}

		if parser.scanner.Peek() == scanner.EOF {
			break
		}
	}
	return &parser.testCase, nil
}

func (p *Parser) parseBlock() error {
	var tok rune
	for tok = p.scanner.Scan(); tok != scanner.EOF; tok = p.scanner.Scan() {
		if tok == '\n' {
			continue
		}
		pos := p.scanner.Position
		kw := p.scanner.TokenText()
		switch kw {
		case "#":
			p.skipComment()
		case "TAGS":
			if err := p.parseTags(); err != nil {
				return err
			}
		case "EGRESS", "INGRESS":
			desc, err := p.parseDescription()
			if err != nil {
				return err
			}

			matchers, err := p.parseMatchers()
			if err != nil {
				return err
			}

			// TODO better errors if ?? etc. used in a ingress/egress block.
			var payload []byte
			for _, m := range matchers {
				payload = append(payload, m.Serialize()...)
			}

			var step TestStep
			if kw == "EGRESS" {
				step = &TestStepEgress{pos, desc, payload}
			} else {
				step = &TestStepIngress{pos, desc, payload}
			}
			p.testCase.Steps = append(p.testCase.Steps, step)

		case "EVENT":
			op, err := p.parseOp()
			if err != nil {
				return err
			}
			matchers, err := p.parseMatchers()
			if err != nil {
				return err
			}
			p.testCase.Steps = append(p.testCase.Steps, &TestStepEvent{pos, op, matchers})

		case "EVENTDUMP":
			op, err := p.parseOp()
			if err != nil {
				return err
			}
			p.testCase.Steps = append(p.testCase.Steps, &TestStepEventDump{pos, op})

		default:
			return fmt.Errorf("unknown keyword '%s'", kw)
		}

	}
	return nil
}

func (p *Parser) parseTags() error {
	for tok := p.scanner.Scan(); tok != scanner.EOF; tok = p.scanner.Scan() {
		if tok == '\n' {
			return nil
		}
		p.testCase.Tags = append(p.testCase.Tags, p.scanner.TokenText())
	}
	return nil
}

func (p *Parser) parseOp() (int, error) {
	tok := p.scanner.Scan()
	if tok == scanner.EOF {
		return 0, fmt.Errorf("EOF when scanning event op")
	}
	switch p.scanner.TokenText() {
	case "TLS", "tls":
		return api.MSG_OP_TLS, nil
	case "HTTP", "http":
		return api.MSG_OP_HTTP, nil
	default:
		return 0, fmt.Errorf("unrecognized event op '%s", p.scanner.TokenText())
	}
}

func (p *Parser) parseDescription() (string, error) {
	var desc []string
	for tok := p.scanner.Scan(); tok != scanner.EOF; tok = p.scanner.Scan() {
		if tok == '\n' {
			break
		}
		if tok == '#' {
			p.skipComment()
			break
		}
		desc = append(desc, p.scanner.TokenText())
	}
	return strings.Join(desc, " "), nil
}

func (p *Parser) skipComment() {
	for tok := p.scanner.Scan(); tok != scanner.EOF; tok = p.scanner.Scan() {
		if tok == '\n' {
			break
		}
	}
}

func (p *Parser) scanInt() (uint64, bool, error) {
	stop := false
	numString := ""
	for {
		tok := p.scanner.Scan()

		if tok == '\n' || tok == '#' || tok == scanner.EOF {
			if tok == '#' {
				p.skipComment()
			}
			stop = true
			break
		}
		numString += p.scanner.TokenText()
	}
	n, err := strconv.ParseUint(numString, 10, 64)
	return n, stop, err
}

func (p *Parser) parseMatchers() (ams []AnnMatcher, err error) {
scan:
	for tok := p.scanner.Scan(); tok != scanner.EOF; tok = p.scanner.Scan() {
		pos := p.scanner.Position
		var ms []Matcher
		switch tok {
		case '\n':
			continue scan

		case scanner.String, scanner.RawString:
			text := p.scanner.TokenText()
			text, _ = strconv.Unquote(text)
			text = strings.ReplaceAll(text, "\\r", "\r")
			text = strings.ReplaceAll(text, "\\n", "\n")
			ms, err = []Matcher{StringMatcher(text)}, nil

		default:
			switch p.scanner.TokenText() {
			case "#":
				p.skipComment()
				goto scan
			case "I":
				ms, err = p.parseIPMatcher()
			case "$":
				ms, err = p.parseHexMatcher()
			case "2":
				ms, err = p.parseHalfWord(true)
			case "h2":
				ms, err = p.parseHalfWord(false)
			case "4":
				ms, err = p.parseWord(true)
			case "h4":
				ms, err = p.parseWord(false)
			case "?":
				ms, err = p.parseWildcard()
			case "END":
				return
			default:
				return nil, fmt.Errorf("unexpected token '%s', expected data line or END", p.scanner.TokenText())
			}
		}

		if err != nil {
			return nil, err
		}
		for _, m := range ms {
			// TODO position too coarse?
			ams = append(ams, AnnMatcher{m, pos})
		}
	}
	return
}

func (p *Parser) parseWildcard() (ms []Matcher, err error) {
	n, _, err := p.scanInt()
	if err != nil {
		return nil, err
	}
	return []Matcher{WildcardMatcher(int(n))}, nil
}

func (p *Parser) parseHalfWord(network bool) (ms []Matcher, err error) {
	for {
		n, stop, err := p.scanInt()
		if err != nil {
			return nil, err
		}

		var bm BytesMatcher = make([]byte, 2)
		if network {
			binary.BigEndian.PutUint16(bm, uint16(n))
		} else {
			native_endian.NativeEndian().PutUint16(bm, uint16(n))
		}
		ms = append(ms, bm)

		if stop {
			break
		}
	}
	return
}

func (p *Parser) parseWord(network bool) (ms []Matcher, err error) {
	for {
		n, stop, err := p.scanInt()
		if err != nil {
			return nil, err
		}

		var bm BytesMatcher = make([]byte, 4)
		if network {
			binary.BigEndian.PutUint32(bm, uint32(n))
		} else {
			native_endian.NativeEndian().PutUint32(bm, uint32(n))
		}
		ms = append(ms, bm)

		if stop {
			break
		}
	}
	return
}

func (p *Parser) parseIPMatcher() (ms []Matcher, err error) {
	text := ""
	for tok := p.scanner.Scan(); tok != scanner.EOF; tok = p.scanner.Scan() {
		if tok == '#' {
			p.skipComment()
			break
		} else if tok == scanner.EOF || tok == '\n' {
			break
		} else {
			text += p.scanner.TokenText()
		}
	}
	addr := net.ParseIP(text)
	if addr == nil {
		return nil, fmt.Errorf("failed to parse IP '%s'", text)
	}
	// TODO support IPv6 as well.
	return []Matcher{BytesMatcher(addr.To4())}, nil
}

func (p *Parser) parseHexMatcher() (ms []Matcher, err error) {
	var hexString string
	emit := func() error {
		bs, err := hex.DecodeString(hexString)
		if err != nil {
			return err
		}
		ms = append(ms, BytesMatcher(bs))
		hexString = ""
		return nil
	}

	for tok := p.scanner.Scan(); tok != scanner.EOF; tok = p.scanner.Scan() {
		if tok == '\n' {
			err = emit()
			return
		}
		if tok == '#' {
			err = emit()
			p.skipComment()
			return
		}
		text := p.scanner.TokenText()

		// TODO collapse repeated?
		if text == "?" && p.scanner.Peek() == '?' {
			p.scanner.Scan()
			err = emit()
			if err != nil {
				return
			}
			ms = append(ms, WildcardMatcher(1))
		} else {
			hexString += text
		}
	}
	return nil, fmt.Errorf("EOF while parsing hex matcher")
}

func (p *Parser) parseStringMatcher() ([]Matcher, error) {
	sm := ""
	for tok := p.scanner.Scan(); tok != scanner.EOF; tok = p.scanner.Scan() {
		if tok == '\n' || tok == '#' {
			if tok == '#' {
				p.skipComment()
			}
			sm = strings.ReplaceAll(sm, "\\r", "\r")
			sm = strings.ReplaceAll(sm, "\\n", "\n")
			return []Matcher{StringMatcher(sm)}, nil
		}
		sm += p.scanner.TokenText()
	}
	return nil, fmt.Errorf("EOF while parsing string")
}

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
	// TODO make sure we get parse error if we try to use a wildcard in ingress/egress.
	panic("Cannot serialize a wildcard")
}
