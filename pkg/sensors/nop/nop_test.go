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
	"fmt"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/nop"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	tusee "github.com/isovalent/hubble-fgs/pkg/testutils/sensors"
)

func TestMain(m *testing.M) {
	ec := runner.TestSensorsRun(m, "SensorNop")
	os.Exit(ec)
}

func nopConfig(port int) string {
	return fmt.Sprintf(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
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
	base := base.GetInitialSensor()
	tus.LoadSensor(t, base)
	yaml := nopConfig(1337)
	policy, err := tracingpolicy.FromYAML(yaml)
	require.NoError(t, err)
	sens, err := sensors.SensorsFromPolicy(policy, policyfilter.NoFilterID)
	require.NoError(t, err)
	for _, si := range sens {
		s := si.(*sensors.Sensor)
		if s != nil {
			tus.LoadSensor(t, s)
		}
	}
}

func TestLoadNopSensor(t *testing.T) {
	base := base.GetInitialSensor()
	tus.LoadSensor(t, base)
	yaml := nopConfig(1337)
	policy, err := tracingpolicy.FromYAML(yaml)
	require.NoError(t, err)
	sensorsi, err := sensors.SensorsFromPolicy(policy, policyfilter.NoFilterID)
	require.NoError(t, err)
	sens := make([]*sensors.Sensor, 0, len(sensorsi))
	sens = append(sens, base)
	for _, si := range sensorsi {
		s := si.(*sensors.Sensor)
		if s != nil {
			tus.LoadSensor(t, s)
			sens = append(sens, s)
		}
	}

	var sensorProgs []tus.SensorProg
	var sensorMaps []tus.SensorMap

	if kernels.MinKernelVersion("5.8.0") {
		sensorProgs = []tus.SensorProg{
			0: tus.SensorProg{Name: "tg_sockmap", Type: ebpf.SockOps},
			1: tus.SensorProg{Name: "tg_nop_sk_msg_fgs", Type: ebpf.SkMsg},
			2: tus.SensorProg{Name: "tg_skskb_http_verdict", Type: ebpf.SkSKB},
		}

		sensorMaps = []tus.SensorMap{
			// maps are loaded only in tg_sockmap program
			tus.SensorMap{Name: "tg_nop_sock_map", Progs: []uint{0}},
			tus.SensorMap{Name: "tg_http_sock_map", Progs: []uint{0}},
			tus.SensorMap{Name: "tg_tls_sock_map", Progs: []uint{0}},
			tus.SensorMap{Name: "tg_nop_filter_map", Progs: []uint{0}},
			tus.SensorMap{Name: "tg_http_filter_map", Progs: []uint{0}},
			tus.SensorMap{Name: "tg_tls_filter_map", Progs: []uint{0}},
		}
	} else {
		sensorProgs = []tus.SensorProg{
			0: tus.SensorProg{Name: "tg_nop_sk_msg_fgs", Type: ebpf.SkMsg},
			1: tus.SensorProg{Name: "tg_skskb_http_verdict", Type: ebpf.SkSKB},
		}
	}

	if utils.SkSkbParserRequired() {
		sensorProgs = append(sensorProgs, tus.SensorProg{Name: "tg_skskb_nop_parser", Type: ebpf.SkSKB})
	}

	assert.NoError(t, err, "nop sensor should load")

	tusee.CheckSensorLoad(sens, sensorMaps, sensorProgs, t)
}
