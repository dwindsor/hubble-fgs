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
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker/yaml"
	"github.com/cilium/tetragon/pkg/crdutils"
	"github.com/cilium/tetragon/pkg/eventcheckertests/yamlhelpers"
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

func TestExamplesEventchecker(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	examplesDir := filepath.Join(filepath.Dir(filename), "../../crds/eventchecker")
	err := filepath.Walk(examplesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories and non-yaml files
		if info.IsDir() || (!strings.HasSuffix(info.Name(), "yaml") && !strings.HasSuffix(info.Name(), "yml")) {
			return nil
		}

		// Fill this in with template data as needed
		templateData := map[string]string{
			"Pid": fmt.Sprint(os.Getpid()),
		}

		// Attempt to parse the file
		data, err := crdutils.ReadFileTemplate(path, templateData)
		assert.NoError(t, err, "example %s must parse correctly", info.Name())

		var conf yaml.EventCheckerConf
		yamlhelpers.AssertUnmarshalRoundTrip(t, []byte(data), &conf)

		return nil
	})

	assert.NoError(t, err, "failed to walk examples directory")
}
