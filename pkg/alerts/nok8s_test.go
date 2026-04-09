// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build nok8s

package alerts

import (
	"strings"
	"testing"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/google/go-cmp/cmp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestRuleFromYAML(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
		want    *v1alpha1.AlertRule
	}{
		{
			name: "valid AlertRule",
			yaml: `
apiVersion: cilium.io/v1alpha1
kind: AlertRule
metadata:
  name: detect-curl
spec:
  expression: "ev.process.binary == '/usr/bin/curl'"
  severity: warning
  message: "curl detected"
  tags:
    - network
    - suspicious
  risk_score: 42
`,
			want: &v1alpha1.AlertRule{
				TypeMeta: metav1.TypeMeta{
					Kind:       "AlertRule",
					APIVersion: "cilium.io/v1alpha1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "detect-curl",
				},
				Spec: v1alpha1.AlertRuleSpec{
					Expression: "ev.process.binary == '/usr/bin/curl'",
					Severity:   "warning",
					Message:    "curl detected",
					Tags:       []string{"network", "suspicious"},
					RiskScore:  42,
				},
			},
		},
		{
			name: "minimal AlertRule",
			yaml: `
apiVersion: cilium.io/v1alpha1
kind: AlertRule
metadata:
  name: minimal
spec:
  expression: "true"
`,
			want: &v1alpha1.AlertRule{
				TypeMeta: metav1.TypeMeta{
					Kind:       "AlertRule",
					APIVersion: "cilium.io/v1alpha1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "minimal",
				},
				Spec: v1alpha1.AlertRuleSpec{
					Expression: "true",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RuleFromYAML(tt.yaml)
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
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("RuleFromYAML() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
