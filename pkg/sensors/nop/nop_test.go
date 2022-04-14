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
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/isovalent/hubble-fgs/pkg/bpf"
	"github.com/isovalent/hubble-fgs/pkg/observer"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/nop"
	"github.com/stretchr/testify/assert"
)

var (
	selfBinary  string
	fgsLib      string
	cmdWaitTime time.Duration
)

const (
	testConfigFile = "/tmp/hubble-fgs.gotest.yaml"
)

func init() {
	flag.StringVar(&fgsLib, "hubble-lib", "../../../bpf/objs/", "hubble lib directory (location of btf file and bpf objs). Will be overridden by an FGS_LIB env variable.")
	flag.DurationVar(&cmdWaitTime, "command-wait", 20000*time.Millisecond, "duration to wait for fgs to gather logs from commands")
}

func TestMain(m *testing.M) {
	flag.Parse()
	bpf.CheckOrMountFS("")
	bpf.CheckOrMountDebugFS()
	bpf.ConfigureResourceLimits()
	selfBinary = filepath.Base(os.Args[0])
	exitCode := m.Run()
	os.Exit(exitCode)
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

	_, err := observer.GetDefaultObserverWithLib(t, testConfigFile, fgsLib)
	assert.NoError(t, err, "nop sensor should load")
}
