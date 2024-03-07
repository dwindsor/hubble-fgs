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
	"os"
	"testing"
	"time"

	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/http"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/layer3"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/sockmap"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/sockops"
)

var expectedPacketPayload = []byte{
	22, 22, 63, 170, 139, 122, 23, 211, 11, 59, 222, 127, 105, 188, 168, 80, 55,
	98, 60, 170, 139, 122, 23, 211, 11, 59, 222, 127, 105, 188, 168, 80, 55, 98,
	60, 170, 139, 122, 23, 211, 11, 59, 222, 127, 105, 188, 168, 80, 55, 98, 60,
	185, 127, 63, 22, 199, 255, 255, 255, 255, 255, 255, 199, 127, 0, 0, 1, 0, 0,
	0, 0, 255, 255, 255, 255, 102, 111, 111, 98, 97, 114, 102, 111, 111, 98, 97,
	114, 98, 97, 122, 13, 10, 10, 97, 32, 114, 97, 119, 32, 115, 116, 114, 105,
	110, 103, 10, 1, 63, 18, 31, 104, 101, 108, 108, 111, 119, 111, 114, 108, 100,
}

const testfileLocation = "testdata/parser/parser-testfile"

func TestParse(t *testing.T) {
	if _, err := os.Stat(testfileLocation); err != nil {
		t.Logf("skipping as testdata/parser-testfile not found")
		return
	}

	tc, err := ParseTestCase(testfileLocation)
	if err != nil {
		t.Errorf("parse of parser-testfile failed: %s", err)
	}
	if tc == nil {
		t.Fatalf("nil *TestCase")
	}

	expected := TestCaseTester{
		Name:        "parser-testfile",
		IngressPort: 8888,
		EgressPort:  9999,
		Tags:        []string{"foo", "bar"},
		Steps: []TestStepTester{
			&TestStepEgressTester{
				Description: "test egress",
				Data:        expectedPacketPayload,
			},
			&TestStepIngressTester{
				Description: "test ingress",
				Data:        expectedPacketPayload,
			},
			&TestStepEventTester{
				Op:   ops.MSG_OP_TLS,
				Data: expectedPacketPayload,
			},
			&TestStepEventDumpTester{
				Op:     ops.MSG_OP_HTTP,
				OpName: "HTTP",
			},
			&TestStepSleepTester{
				Duration: time.Second,
			},
			&TestStepSleepTester{
				Duration: time.Minute + 30*time.Second,
			},
		},
	}

	expected.Assert(t, tc)
}
