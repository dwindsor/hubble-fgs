// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build nok8s && nok8s_test

package sandboxpolicy

import (
	"strings"
	"testing"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/google/go-cmp/cmp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestFromYAML(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
		want    *v1alpha1.SandboxPolicy
	}{
		{
			name: "valid SandboxPolicy",
			yaml: `
apiVersion: cilium.io/v1alpha1
kind: SandboxPolicy
metadata:
  name: restrict-syscalls
spec:
  syscalls:
    - list:
        - name: "openat"
        - name: "read"
      op: "In"
      actions:
        - type: "Post"
`,
			want: &v1alpha1.SandboxPolicy{
				TypeMeta: metav1.TypeMeta{
					Kind:       "SandboxPolicy",
					APIVersion: "cilium.io/v1alpha1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "restrict-syscalls",
				},
				Spec: v1alpha1.SandboxSpec{
					Syscalls: []v1alpha1.SandboxSyscallsSpec{
						{
							List: []v1alpha1.SandboxSyscallItem{
								{Name: "openat"},
								{Name: "read"},
							},
							Op: "In",
							Actions: []v1alpha1.SandboxAction{
								{Type: "Post"},
							},
						},
					},
				},
			},
		},
		{
			name: "minimal SandboxPolicy",
			yaml: `
apiVersion: cilium.io/v1alpha1
kind: SandboxPolicy
metadata:
  name: empty
spec: {}
`,
			want: &v1alpha1.SandboxPolicy{
				TypeMeta: metav1.TypeMeta{
					Kind:       "SandboxPolicy",
					APIVersion: "cilium.io/v1alpha1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "empty",
				},
			},
		},
		{
			name: "unknown top-level field",
			yaml: `
apiVersion: cilium.io/v1alpha1
kind: SandboxPolicy
metadata:
  name: unknown-top-level
unknown: true
spec:
  syscalls: []
`,
			wantErr: "failed to unmarshal Sandboxpolicy",
		},
		{
			name: "unknown metadata field",
			yaml: `
apiVersion: cilium.io/v1alpha1
kind: SandboxPolicy
metadata:
  name: unknown-metadata
  unknown: true
spec:
  syscalls: []
`,
			wantErr: "failed to unmarshal Sandboxpolicy",
		},
		{
			name: "unknown spec field",
			yaml: `
apiVersion: cilium.io/v1alpha1
kind: SandboxPolicy
metadata:
  name: unknown-spec
spec:
  syscals: []
`,
			wantErr: "failed to unmarshal Sandboxpolicy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := FromYAML(tt.yaml)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			got, ok := result.(*v1alpha1.SandboxPolicy)
			if !ok {
				t.Fatalf("expected *v1alpha1.SandboxPolicy, got %T", result)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("FromYAML() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
