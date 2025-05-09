//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

// The purpose of the examples_test package is to validate that example
// configuration/policy files are syntactically valid.
package examples_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"github.com/cilium/tetragon/pkg/crdutils"
	"github.com/isovalent/hubble-fgs/pkg/alerts"
	"github.com/isovalent/hubble-fgs/pkg/netpol"
)

func TestExamplesTracingPolicy(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	examplesDir := filepath.Join(filepath.Dir(filename), "../../examples/tracingpolicy")
	crdutils.CheckPolicies(t, examplesDir, func(path string) error {
		data := map[string]string{
			"Pid": strconv.Itoa(os.Getpid()),
		}
		_, err := crdutils.FileConfigWithTemplate(path, data)
		return err
	})
}

func TestExamplesAlertRule(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	examplesDir := filepath.Join(filepath.Dir(filename), "../../examples/alertrule")
	crdutils.CheckPolicies(t, examplesDir, func(path string) error {
		_, err := alerts.FromFile(path)
		return err
	})
}

func TestExamplesTetragonNetworkPolicy(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	examplesDir := filepath.Join(filepath.Dir(filename), "../../examples/tetragonnetworkpolicy")
	crdutils.CheckPolicies(t, examplesDir, func(path string) error {
		_, err := netpol.FromFile(path)
		return err
	})
}
