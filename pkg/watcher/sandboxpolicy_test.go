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

package watcher

import (
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

func TestNeedSandboxpolicyUpdate(t *testing.T) {
	type fnRet int
	const (
		errRet fnRet = iota
		updateRet
		skipRet
	)

	type tc struct {
		newObj, oldObj interface{}
		expected       fnRet
	}

	tcs := []tc{
		{
			newObj:   &v1alpha1.SandboxPolicy{ObjectMeta: metav1.ObjectMeta{ResourceVersion: "pizza"}},
			oldObj:   &v1alpha1.SandboxPolicy{ObjectMeta: metav1.ObjectMeta{ResourceVersion: "carrot"}},
			expected: updateRet,
		},
		{
			newObj:   &v1alpha1.SandboxPolicy{ObjectMeta: metav1.ObjectMeta{ResourceVersion: "pizza"}},
			oldObj:   &v1alpha1.SandboxPolicy{ObjectMeta: metav1.ObjectMeta{ResourceVersion: "pizza"}},
			expected: skipRet,
		},
		{
			newObj:   &v1alpha1.SandboxPolicyNamespaced{ObjectMeta: metav1.ObjectMeta{ResourceVersion: "pizza"}},
			oldObj:   &v1alpha1.SandboxPolicyNamespaced{ObjectMeta: metav1.ObjectMeta{ResourceVersion: "carrot"}},
			expected: updateRet,
		},
		{
			newObj:   &v1alpha1.SandboxPolicyNamespaced{ObjectMeta: metav1.ObjectMeta{ResourceVersion: "pizza"}},
			oldObj:   &v1alpha1.SandboxPolicyNamespaced{ObjectMeta: metav1.ObjectMeta{ResourceVersion: "pizza"}},
			expected: skipRet,
		},
		{
			newObj:   &v1alpha1.SandboxPolicy{ObjectMeta: metav1.ObjectMeta{ResourceVersion: "pizza"}},
			oldObj:   &v1alpha1.SandboxPolicyNamespaced{ObjectMeta: metav1.ObjectMeta{ResourceVersion: "pizza"}},
			expected: errRet,
		},
		{
			newObj:   &v1alpha1.SandboxPolicyNamespaced{ObjectMeta: metav1.ObjectMeta{ResourceVersion: "pizza"}},
			oldObj:   &v1alpha1.SandboxPolicy{ObjectMeta: metav1.ObjectMeta{ResourceVersion: "pizza"}},
			expected: errRet,
		},
	}

	for i := range tcs {
		tc := tcs[i]
		upd, err := sandboxPolicyNeedsUpdate(tc.oldObj, tc.newObj)
		switch tc.expected {
		case errRet:
			require.NotNil(t, err)
		case updateRet:
			require.NoError(t, err)
			require.Equal(t, true, upd)
		case skipRet:
			require.NoError(t, err)
			require.Equal(t, false, upd)
		default:
			require.Equal(t, true, false)
		}
	}
}
