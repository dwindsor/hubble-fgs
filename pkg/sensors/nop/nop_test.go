// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build sudo_tests

package nop_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	enterpriseoth "github.com/isovalent/hubble-fgs/pkg/observer/observertesthelper"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	"github.com/isovalent/hubble-fgs/pkg/sensors/nop"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/nop"
	"github.com/isovalent/hubble-fgs/pkg/sensors/sockops"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
	cli "github.com/isovalent/hubble-fgs/pkg/testutils/cliswitches"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"

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

func testNopSensorSmoke(t *testing.T, CLISwitches bool) {
	base := base.GetInitialSensorTest(t)
	tus.LoadSensor(t, base)
	yaml := nopConfig(1337)

	if CLISwitches {
		require.NoError(t, cli.SetSwitches(t, []cli.SwitchSettings{
			{KeyPtr: &enterpriseOption.Config.EnableNopSensor, Value: true},
			{KeyPtr: &enterpriseOption.Config.NopSensorPorts, Value: []int{1337}},
		}))
		yaml = enterpriseoth.EmptyTracingPolicy
	}
	policy, err := tracingpolicy.FromYAML(yaml)
	require.NoError(t, err)
	sens, err := sensors.SensorsFromPolicy(policy, policyfilter.NoFilterID)
	require.NoError(t, err)
	if CLISwitches {
		sockopsSensor, err := sockops.Builder(&tracingpolicy.GenericTracingPolicy{}, "__sockops_init_sensors__")
		require.NoError(t, err)
		if sockopsSensor != nil {
			sens = append(sens, sockopsSensor)
		}
		nopSensor := nop.EnableNopParser(&tracingpolicy.GenericTracingPolicy{})
		if nopSensor != nil {
			sens = append(sens, nopSensor)
		}
	}
	for _, si := range sens {
		s := si.(*sensors.Sensor)
		if s != nil {
			tus.LoadSensor(t, s)
		}
	}
	logger.GetLogger().Warn("unload", "sens", sens)
	sensors.UnloadSensors(sens)
}

func TestNopSensorSmoke(t *testing.T) {
	testNopSensorSmoke(t, false)
}

func TestNopSensorSmokeCLI(t *testing.T) {
	testNopSensorSmoke(t, true)
}

func testLoadNopSensor(t *testing.T, CLISwitches bool) {
	base := base.GetInitialSensorTest(t)
	option.Config.KeepCollection = true
	defer func() { option.Config.KeepCollection = false }()
	tus.LoadSensor(t, base)
	yaml := nopConfig(1337)

	if CLISwitches {
		require.NoError(t, cli.SetSwitches(t, []cli.SwitchSettings{
			{KeyPtr: &enterpriseOption.Config.EnableNopSensor, Value: true},
			{KeyPtr: &enterpriseOption.Config.NopSensorPorts, Value: []int{1337}},
		}))
		yaml = enterpriseoth.EmptyTracingPolicy
	}
	policy, err := tracingpolicy.FromYAML(yaml)
	require.NoError(t, err)
	sensorsi, err := sensors.SensorsFromPolicy(policy, policyfilter.NoFilterID)
	require.NoError(t, err)
	if CLISwitches {
		sockopsSensor, err := sockops.Builder(&tracingpolicy.GenericTracingPolicy{}, "__sockops_init_sensors__")
		require.NoError(t, err)
		if sockopsSensor != nil {
			sensorsi = append(sensorsi, sockopsSensor)
		}
		nopSensor := nop.EnableNopParser(&tracingpolicy.GenericTracingPolicy{})
		if nopSensor != nil {
			sensorsi = append(sensorsi, nopSensor)
		}
	}
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

	sensors.UnloadSensors(sensorsi)
}

func TestLoadNopSensor(t *testing.T) {
	testLoadNopSensor(t, false)
}

func TestLoadNopSensorCLI(t *testing.T) {
	testLoadNopSensor(t, true)
}
