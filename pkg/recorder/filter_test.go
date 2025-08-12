// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package recorder

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"sigs.k8s.io/yaml"

	ecYaml "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker/yaml"
)

func TestFieldFilters(t *testing.T) {
	checkerYaml := `
    exec:
      parent:
        arguments:
          operator: full
          value: -c "PORT=9080 node server.js"
        binary:
          operator: suffix
          value: /sh
      process:
        pid: 1337
        arguments:
          operator: contains
          value: server.js
        binary:
          operator: suffix
          value: /node
        pod:
          container:
            image:
              name:
                operator: full
                value: quay.io/isovalent/jobs-app-jobposting:latest
            name:
              operator: full
              value: jobposting
          name:
            operator: prefix
            value: jobposting
          namespace:
            operator: full
            value: tenant-jobs
    `
	checker := ecYaml.EventChecker{}
	if !assert.NoError(t, yaml.Unmarshal([]byte(checkerYaml), &checker)) {
		return
	}

	filter := CheckerFieldFilters{
		Include: []string{"parent.binary", "process"},
		Exclude: []string{"process.pod", "process.pid"},
	}
	filteredChecker, err := FilterCheckerFields(&filter, checker.EventChecker)
	if !assert.NoError(t, err) {
		return
	}

	expectedCheckerYaml := `
    exec:
      parent:
        binary:
          operator: suffix
          value: /sh
      process:
        arguments:
          operator: contains
          value: server.js
        binary:
          operator: suffix
          value: /node
    `
	expectedChecker := ecYaml.EventChecker{}
	if !assert.NoError(t, yaml.Unmarshal([]byte(expectedCheckerYaml), &expectedChecker)) {
		return
	}

	filtered, _ := json.MarshalIndent(filteredChecker, "", "  ")
	expected, _ := json.MarshalIndent(expectedChecker.EventChecker, "", "  ")

	fmt.Println(string(filtered))

	assert.Equal(t, string(filtered), string(expected))
}

func TestFixupPathCase(t *testing.T) {
	path := "foo.BaR.quX.BAZ"
	expected := "Foo.BaR.QuX.BAZ"
	actual := fixupPathStringCase(path)

	assert.Equal(t, actual, expected)
}
