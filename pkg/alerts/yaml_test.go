//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package alerts

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

func TestMessageTooLong(t *testing.T) {
	var a = `
apiVersion: cilium.io/v1alpha1
kind: AlertRule
metadata:
  name: test
spec:
  expression: "test == 1"
  message: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  severity: info

`
	_, err := FromYAML(a)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "validation failed: spec.message in body should be at most 256 chars long")
}

func TestRepeatedTags(t *testing.T) {
	var a = `
apiVersion: cilium.io/v1alpha1
kind: AlertRule
metadata:
  name: test
spec:
  expression: "test == 1"
  tags: ["test", "test"]
  severity: info
`
	_, err := FromYAML(a)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "validation failed: spec.tags[1]: Duplicate value: \"test\"")
}

func TestTooManyTags(t *testing.T) {
	var a = `
apiVersion: cilium.io/v1alpha1
kind: AlertRule
metadata:
  name: test
spec:
  expression: "test == 1"
  tags: ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17"]
  severity: info

`
	_, err := FromYAML(a)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "validation failed: spec.tags in body should have at most 16 items")
}

func TestDefaultSeverity(t *testing.T) {
	var a = `
apiVersion: cilium.io/v1alpha1
kind: AlertRule
metadata:
  name: test
spec:
  expression: "test == 1"
`
	rule, err := FromYAML(a)
	assert.NoError(t, err)
	ar := rule.(*v1alpha1.AlertRule)
	assert.Equal(t, "info", ar.Spec.Severity)
}

func TestInvalidSeverity(t *testing.T) {
	var a = `
apiVersion: cilium.io/v1alpha1
kind: AlertRule
metadata:
  name: test
spec:
  expression: "test == 1"
  severity: error
`
	_, err := FromYAML(a)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "validation failed: spec.severity in body should be one of [critical warning info]")
}

func TestExamplesSmoke(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	examplesDir := filepath.Join(filepath.Dir(filename), "../../examples/alertrule")
	err := filepath.Walk(examplesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip non-directories and non-yaml files
		if info.IsDir() || !strings.HasSuffix(info.Name(), "yaml") || strings.HasSuffix(info.Name(), "yml") {
			return nil
		}

		// Attempt to parse the file
		_, err = FromFile(path)
		assert.NoError(t, err, "example %s must parse correctly: %s", info.Name(), err)

		return nil
	})

	assert.NoError(t, err, "failed to walk examples directory")
}
