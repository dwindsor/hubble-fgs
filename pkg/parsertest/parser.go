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
	"encoding/binary"
	"encoding/hex"
	"fmt"
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
	parser.scanner.Filename = path.Base(file)
	parser.scanner.Whitespace ^= 1 << '\n'
	parser.scanner.Mode =
		scanner.ScanComments | scanner.SkipComments | scanner.ScanIdents | scanner.ScanStrings | scanner.ScanRawStrings
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
			op, _, err := p.parseOp()
			if err != nil {
				return err
			}
			matchers, err := p.parseMatchers()
			if err != nil {
				return err
			}
			p.testCase.Steps = append(p.testCase.Steps, &TestStepEvent{pos, op, matchers})

		case "EVENTDUMP":
			op, name, err := p.parseOp()
			if err != nil {
				return err
			}
			p.testCase.Steps = append(p.testCase.Steps, &TestStepEventDump{pos, op, name})

		case "CLOSE":
			dir, err := p.parseCloseDirection()
			if err != nil {
				return err
			}
			p.testCase.Steps = append(p.testCase.Steps, &TestStepClose{pos, dir})

		case "ASSERT":
			a, err := p.parseAssert()
			if err != nil {
				return err
			}
			p.testCase.Steps = append(p.testCase.Steps, a)

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

func (p *Parser) parseOp() (int, string, error) {
	tok := p.scanner.Scan()
	if tok == scanner.EOF {
		return 0, "", fmt.Errorf("EOF when parsing event op")
	}
	name := strings.ToUpper(p.scanner.TokenText())

	switch name {
	case "TLS":
		return api.MSG_OP_TLS, name, nil
	case "TLSCONT":
		return api.MSG_OP_TLS_CONT, name, nil
	case "HTTP":
		return api.MSG_OP_HTTP, name, nil
	case "TCPCONNECT":
		return api.MSG_OP_IPV4_TCPCONNECT, name, nil
	case "TCPCONNECTRET":
		return api.MSG_OP_IPV4_TCPCONNECTRET, name, nil
	case "TCPACCEPT":
		return api.MSG_OP_IPV4_ACCEPT, name, nil
	case "TCPCLOSE":
		return api.MSG_OP_IPV4_TCPCLOSE, name, nil
	case "TCPSTATS":
		return api.MSG_OP_IPV4_TCPSTATS, name, nil
	default:
		return 0, name, fmt.Errorf("unrecognized event op '%s", p.scanner.TokenText())
	}
}

func (p *Parser) parseCloseDirection() (int, error) {
	tok := p.scanner.Scan()
	if tok == scanner.EOF {
		return 0, fmt.Errorf("EOF when parsing close direction")
	}
	if tok == '\n' || tok == '#' {
		return CLOSE_BOTH, nil
	}

	switch strings.ToUpper(p.scanner.TokenText()) {
	case "CLIENT":
		return CLOSE_CLIENT, nil
	case "SERVER":
		return CLOSE_SERVER, nil
	case "BOTH":
		return CLOSE_BOTH, nil
	default:
		return 0, fmt.Errorf("expected CLIENT/SERVER/BOTH for CLOSE")
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

func (p *Parser) parseIdent() (string, error) {
	tok := p.scanner.Scan()

	if tok == scanner.EOF {
		return "", fmt.Errorf("EOF when parsing identifier")
	}
	if tok == '\n' || tok == '#' {
		return "", fmt.Errorf("unexpected newline or comment when expecting identifier")
	}

	return p.scanner.TokenText(), nil
}

func (p *Parser) parseAssert() (*TestStepAssert, error) {
	tok := p.scanner.Scan()
	if tok == scanner.EOF {
		return nil, fmt.Errorf("EOF when scanning event op")
	}
	kind := strings.ToUpper(p.scanner.TokenText())

	switch kind {
	case "MAP": // ASSERT MAP ...
		mapName, err := p.parseIdent()
		if err != nil {
			return nil, err
		}

	skip:
		assertion, err := p.parseIdent()
		if err != nil {
			return nil, err
		}
		switch assertion {
		case "IS", "HAS": // ASSERT MAP foobar IS ...
			goto skip

		case "COUNT": // ASSERT MAP foobar HAS COUNT 1
			cnt, _, err := p.scanInt()
			if err != nil {
				return nil, err
			}
			return &TestStepAssert{
				Position: p.scanner.Position,
				MapName:  mapName,
				Type:     AssertMapCount,
				Count:    int(cnt),
			}, nil

		case "EMPTY": // ASSERT MAP foobar IS EMPTY
			return &TestStepAssert{
				Position: p.scanner.Position,
				MapName:  mapName,
				Type:     AssertMapCount,
				Count:    0,
			}, nil

		default:
			return nil, fmt.Errorf("unknown MAP assertion '%s', expected EMPTY", assertion)

		}

	default:
		return nil, fmt.Errorf("unknown assertion '%s', expected MAP", kind)
	}

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
	base := 10
	if strings.HasPrefix(numString, "0x") {
		base = 16
		numString = numString[2:]
	}

	n, err := strconv.ParseUint(numString, base, 64)
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
			case "A":
				ms, err = p.parseAddrMatcher()
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
			case "8":
				ms, err = p.parseDoubleWord(true)
			case "h8":
				ms, err = p.parseDoubleWord(false)
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

func (p *Parser) parseAddrMatcher() ([]Matcher, error) {
	tok := p.scanner.Scan()
	if tok == scanner.EOF || tok == '\n' || tok == '#' {
		return nil, fmt.Errorf("EOF while parsing addr matcher")
	}
	var m ConnAddrMatcher

	// TODO(JM): the keywords are pretty ugly. figure out something neater.
	switch p.scanner.TokenText() {
	case "SRV_ADDR":
		m.kind = CMK_IP_RAW
	case "CLI_ADDR":
		m.kind = CMK_IP_RAW
		m.isClient = true
	case "SRV_ADDR_STR":
		m.kind = CMK_IP_STRING
	case "CLI_ADDR_STR":
		m.kind = CMK_IP_STRING
		m.isClient = true
	case "SRV_PORT":
		m.kind = CMK_PORT_NET
	case "CLI_PORT":
		m.kind = CMK_PORT_NET
		m.isClient = true
	case "SRV_PORT_HOST":
		m.kind = CMK_PORT_HOST
	case "CLI_PORT_HOST":
		m.isClient = true
		m.kind = CMK_PORT_HOST
	}
	return []Matcher{m}, nil
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

func (p *Parser) parseDoubleWord(network bool) (ms []Matcher, err error) {
	for {
		n, stop, err := p.scanInt()
		if err != nil {
			return nil, err
		}

		var bm BytesMatcher = make([]byte, 8)
		if network {
			binary.BigEndian.PutUint64(bm, n)
		} else {
			native_endian.NativeEndian().PutUint64(bm, n)
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
		if hexString == "" {
			return nil
		}
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
