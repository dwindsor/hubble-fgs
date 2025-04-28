//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

//go:build sudo_tests

// stresstests contains stress tests for various sensors.
package stresstests

import (
	"os"
	"testing"

	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"

	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
)

const testConfigFile = "/tmp/tetragon.gotest.yaml"

func TestMain(m *testing.M) {
	ec := runner.TestSensorsRun(m, "SensorStressTests")
	os.Exit(ec)
}
