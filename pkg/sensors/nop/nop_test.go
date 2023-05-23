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

package nop_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/observer"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/nop"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"
	"github.com/stretchr/testify/assert"

	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
)

const (
	testConfigFile = "/tmp/hubble-tetragon.gotest.yaml"
)

func TestMain(m *testing.M) {
	ec := runner.TestSensorsRun(m, "SensorNop")
	os.Exit(ec)
}

func nopConfig(port int) string {
	return fmt.Sprintf(`
apiVersion: hubble-enterprise.io/v1
metadata:
  name: "nop"
spec:
  parser:
    nop:
      enable: true
      selectors:
      - matchPorts:
        - %d
`, port)
}

func TestNopSensorSmoke(t *testing.T) {
	if err := observer.WriteConfigFile(testConfigFile, nopConfig(int(1337))); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}

	_, err := observer.GetDefaultObserverWithConfig(t, context.Background(), testConfigFile, runner.Conf().TetragonLib, observer.WithMyPid())
	assert.NoError(t, err, "nop sensor should load")
}

func TestLoadNopSensor(t *testing.T) {
	if err := observer.WriteConfigFile(testConfigFile, nopConfig(int(1337))); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}

	sens, err := observer.GetDefaultSensorsWithFile(t, context.TODO(), testConfigFile, runner.Conf().TetragonLib, observer.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultSensorsWithFile error: %s", err)
	}

	var sensorProgs []tus.SensorProg
	var sensorMaps []tus.SensorMap

	if kernels.MinKernelVersion("5.8.0") {
		sensorProgs = []tus.SensorProg{
			0: tus.SensorProg{Name: "bpf_sockmap", Type: ebpf.SockOps},
			1: tus.SensorProg{Name: "bpf_nop_sk_msg_fgs", Type: ebpf.SkMsg},
			2: tus.SensorProg{Name: "bpf_skskb_http_verdict", Type: ebpf.SkSKB},
		}

		sensorMaps = []tus.SensorMap{
			// maps are loaded only in bpf_sockmap program
			tus.SensorMap{Name: "nop_sock_map", Progs: []uint{0}},
			tus.SensorMap{Name: "http_sock_map", Progs: []uint{0}},
			tus.SensorMap{Name: "tls_sock_map", Progs: []uint{0}},
			tus.SensorMap{Name: "nop_filter_map", Progs: []uint{0}},
			tus.SensorMap{Name: "http_filter_map", Progs: []uint{0}},
			tus.SensorMap{Name: "tls_filter_map", Progs: []uint{0}},
		}
	} else {
		sensorProgs = []tus.SensorProg{
			0: tus.SensorProg{Name: "bpf_nop_sk_msg_fgs", Type: ebpf.SkMsg},
			1: tus.SensorProg{Name: "bpf_skskb_http_verdict", Type: ebpf.SkSKB},
		}
	}

	if utils.SkSkbParserRequired() {
		sensorProgs = append(sensorProgs, tus.SensorProg{Name: "bpf_skskb_nop_parser", Type: ebpf.SkSKB})
	}

	assert.NoError(t, err, "nop sensor should load")

	tus.CheckSensorLoad(sens, sensorMaps, sensorProgs, t)
}
