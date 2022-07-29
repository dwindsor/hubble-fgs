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
	"fmt"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/cilium/tetragon/pkg/testutils/sensors"
)

func init() {
	sensors.ConfigDefaults.TetragonLib = filepath.Join(tetragonBpfPath(), "objs")
	fmt.Println("default bpf dir is: ", sensors.ConfigDefaults.TetragonLib)
}

// tetragonBpfPath retrieves bpf code path
func tetragonBpfPath() string {
	_, testFname, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(testFname), "..", "..", "..", "bpf")
}

// TestSensorsRun runs a sensor test. Call this from inside the TestMain() of a sensor
// test. It returns an exit code.
func TestSensorsRun(m *testing.M, sensorName string) int {
	return sensors.TestSensorsRun(m, sensorName)
}

func Conf() *sensors.Config {
	return sensors.Conf()
}
