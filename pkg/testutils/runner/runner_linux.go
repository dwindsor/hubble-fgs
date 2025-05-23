// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package runner

import (
	"testing"

	"github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/isovalent/hubble-fgs/pkg/sensors/program/cgroup"
)

// TestSensorsRun runs a sensor test. Call this from inside the TestMain() of a sensor
// test. It returns an exit code. Additionally will release any Cgroup programs
// that are left because we do not have Cgroup links yet or on all kernels.
func TestSensorsRun(m *testing.M, sensorName string) int {
	defer cgroup.DetachTetragonCgroups(true, false)
	return sensors.TestSensorsRun(m, sensorName)
}
