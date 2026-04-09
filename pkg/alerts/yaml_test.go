// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build !nok8s

package alerts

import (
	"fmt"
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

// We want to avoid file system escapes, since we are using the name as a filename. This is
// currently ensured by k8s validation which ensures that the name is a DNS subdomain name.
// This test is left as a reminder in case we ever change the FromYAML implementation.
func TestRejectSuspiciousNames(t *testing.T) {
	format := `
apiVersion: cilium.io/v1alpha1
kind: AlertRule
metadata:
  name: %s
spec:
  expression: "true"
  severity: "critical"
`
	for _, name := range []string{"/foo", "../", "foo/lala"} {
		_, err := FromYAML(fmt.Sprintf(format, name))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "validation failed: metadata.name: Invalid value")
	}
}
