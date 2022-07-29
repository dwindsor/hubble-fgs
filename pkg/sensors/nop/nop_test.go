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

	"github.com/cilium/tetragon/pkg/observer"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/nop"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"
	"github.com/stretchr/testify/assert"
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

	_, err := observer.GetDefaultObserverWithLib(t, testConfigFile, runner.Conf().TetragonLib)
	assert.NoError(t, err, "nop sensor should load")
}
