// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package sandboxpolicy

import (
	"testing"

	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

func TestValidationDuplicateActions(t *testing.T) {
	var p = `
apiVersion: cilium.io/v1alpha1
kind: SandboxPolicy
metadata:
  name: "syscalls"
spec:
  syscalls:
    - list:
      - name: "sys_dup"
      - name: "sys_dup2"
      op: "In"
      actions:
       - type: "Block"
       - type: "Block"
`
	_, err := FromYAML(p)
	require.Error(t, err)
}

func TestValidationDefaultValues(t *testing.T) {
	var p = `
apiVersion: cilium.io/v1alpha1
kind: SandboxPolicy
metadata:
  name: "syscalls"
spec:
  syscalls:
    - list:
      - name: "sys_dup"
      - name: "sys_dup2"
`

	pol, err := FromYAML(p)
	require.Nil(t, err)
	_, err = yaml.Marshal(pol)
	require.Nil(t, err)
	defaultActions := []v1alpha1.SandboxAction{
		{Type: "Post"},
		{Type: "Block"},
	}
	sp := pol.(*v1alpha1.SandboxPolicy)
	require.Equal(t, "In", sp.Spec.Syscalls[0].Op)
	require.ElementsMatch(t, defaultActions, sp.Spec.Syscalls[0].Actions)
}

func TestValidationNamespaced(t *testing.T) {
	var p = `
apiVersion: cilium.io/v1alpha1
kind: SandboxPolicyNamespaced
metadata:
  name: "syscalls"
  namespace: "default"
spec:
  syscalls:
    - list:
      - name: "sys_dup"
      - name: "sys_dup2"
      op: "In"
      actions:
       - type: "Post"
`
	pol, err := FromYAML(p)
	require.NotNil(t, pol)
	require.Nil(t, err)
}

func TestValidationName(t *testing.T) {
	var p = `
apiVersion: cilium.io/v1alpha1
kind: SandboxPolicyNamespaced
metadata:
  name: "syscalls"
  namespace: "default"
spec:
  syscalls:
    - list:
      - name: "sys_dup"
      op: "In"
      actions:
       - type: "Post"
`
	pol, err := FromYAML(p)
	require.NotNil(t, pol)
	require.Nil(t, err)
	require.Equal(t, pol.GetObjectMetaStruct().Name, "syscalls")
}
