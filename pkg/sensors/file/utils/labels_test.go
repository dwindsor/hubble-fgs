// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

// go test -gcflags="" -c ./pkg/sensors/file/utils -o go-tests/file-utils.test
// ./go-tests/file-utils.test

package file

import (
	"testing"

	"github.com/stretchr/testify/assert"

	slimv1 "github.com/cilium/tetragon/pkg/k8s/slim/k8s/apis/meta/v1"
)

func TestMatchLabelsIn(t *testing.T) {
	s := []slimv1.LabelSelectorRequirement{
		{
			Key:      "io.kubernetes.pod.namespace",
			Operator: "In",
			Values: []string{
				"default",
				"kube-proxy",
			},
		},
	}
	assert.True(t, matchExpressions(s, "default", "app-name"))
	assert.True(t, matchExpressions(s, "kube-proxy", "app-name"))
	assert.False(t, matchExpressions(s, "test-namespace", "app-name"))
}

func TestMatchLabelsNotIn(t *testing.T) {
	s := []slimv1.LabelSelectorRequirement{
		{
			Key:      "io.kubernetes.pod.namespace",
			Operator: "NotIn",
			Values: []string{
				"default",
				"kube-proxy",
			},
		},
	}
	assert.False(t, matchExpressions(s, "default", "app-name"))
	assert.False(t, matchExpressions(s, "kube-proxy", "app-name"))
	assert.True(t, matchExpressions(s, "test-namespace", "app-name"))
}

func TestMatchExpressions(t *testing.T) {
	s := &slimv1.LabelSelector{
		MatchExpressions: []slimv1.LabelSelectorRequirement{
			{
				Key:      "io.kubernetes.pod.namespace",
				Operator: "In",
				Values: []string{
					"kube-proxy",
				},
			},
			{
				Key:      "io.kubernetes.pod.app",
				Operator: "In",
				Values: []string{
					"tetragon",
				},
			},
		},
	}

	assert.True(t, MatchPodSelector(s, "kube-proxy", "tetragon"))
	assert.True(t, MatchPodSelector(s, "kube-proxy", "tetragon-abcde"))
	assert.False(t, MatchPodSelector(s, "kube-proxy", "tetra"))
	assert.False(t, MatchPodSelector(s, "default", "random-gjhad"))
	assert.False(t, MatchPodSelector(s, "ubuntu", "random-gjhad"))
}

func TestMatchLabels(t *testing.T) {
	s := &slimv1.LabelSelector{
		MatchLabels: map[string]slimv1.MatchLabelsValue{
			"io.kubernetes.pod.namespace": "kube-proxy",
			"io.kubernetes.pod.app":       "tetragon",
		},
	}

	assert.True(t, MatchPodSelector(s, "kube-proxy", "tetragon"))
	assert.True(t, MatchPodSelector(s, "kube-proxy", "tetragon-abcde"))
	assert.False(t, MatchPodSelector(s, "kube-proxy", "tetra"))
	assert.False(t, MatchPodSelector(s, "default", "tetragon"))
	assert.False(t, MatchPodSelector(s, "default", "tetra"))
}
