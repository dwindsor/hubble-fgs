package vtuplefilter

import (
	"testing"

	"github.com/isovalent/hubble-fgs/pkg/vtuple"
)

type VTRes struct {
	vt  vtuple.VTupleImpl
	res bool
}

type LineTestCase struct {
	line  string
	tests []VTRes
}

var (
	ip10 = [4]byte{10, 1, 1, 10}
	ip20 = [4]byte{10, 1, 1, 20}

	LineTestCases []LineTestCase = []LineTestCase{
		LineTestCase{
			line: "sport=9999",
			tests: []VTRes{
				VTRes{vt: vtuple.CreateTCPv4(ip10, 9999, ip20, 4242), res: true},
				VTRes{vt: vtuple.CreateTCPv4(ip10, 4242, ip20, 9999), res: false},
				VTRes{vt: vtuple.CreateTCPv4(ip10, 4242, ip20, 1234), res: false},
			},
		},
		LineTestCase{
			line: "dport=9999",
			tests: []VTRes{
				VTRes{vt: vtuple.CreateTCPv4(ip10, 9999, ip20, 4242), res: false},
				VTRes{vt: vtuple.CreateTCPv4(ip10, 4242, ip20, 9999), res: true},
				VTRes{vt: vtuple.CreateTCPv4(ip10, 4242, ip20, 1234), res: false},
			},
		},
		LineTestCase{
			line: "port=9999",
			tests: []VTRes{
				VTRes{vt: vtuple.CreateTCPv4(ip10, 9999, ip20, 4242), res: true},
				VTRes{vt: vtuple.CreateTCPv4(ip10, 4242, ip20, 9999), res: true},
				VTRes{vt: vtuple.CreateTCPv4(ip10, 4242, ip20, 1234), res: false},
			},
		},

		// TODO: more tests
	}
)

func doLineTest(t *testing.T, c *LineTestCase) {
	filter, err := FromLine(c.line)
	if err != nil {
		t.Errorf("failed to parse line %s: %w", c.line, err)
	}

	for _, vtres := range c.tests {
		res := filter.FilterFn(&vtres.vt)
		if res != vtres.res {
			t.Errorf("filter:%s tuple:%s expected_result:%t result:%t", c.line, vtuple.StringRep(&vtres.vt), vtres.res, res)
		}

	}
}

func TestLines(t *testing.T) {
	for _, tc := range LineTestCases {
		doLineTest(t, &tc)
	}
}
