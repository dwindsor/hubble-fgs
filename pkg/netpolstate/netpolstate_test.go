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

package netpolstate

import (
	"os"
	"testing"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/option"

	"github.com/isovalent/hubble-fgs/pkg/model/datapath"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"
)

func TestMain(m *testing.M) {
	bpf.CheckOrMountCgroup2()
	option.Config.EnablePolicyFilter = true
	option.Config.EnablePolicyFilter = true
	option.Config.EnablePolicyFilterCgroupMap = true
	prog = &datapath.DummyBpfProgrammer{}
	ec := runner.TestSensorsRun(m, "ModelDns")
	os.Exit(ec)
}
