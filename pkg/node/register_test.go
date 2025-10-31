// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package node

import (
	"context"
	"testing"

	"github.com/cilium/tetragon/pkg/version"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/isovalent/ipa/k8s/apis/isovalent.com/v1alpha1"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/isovalent/hubble-fgs/pkg/node/local"
)

type fakeMetadataService struct {
	hostName    string
	labels      map[string]string
	instanceID  string
	internalIP  string
	externalIP  string
	internalDNS string
	externalDNS string
}

func (f fakeMetadataService) GetHostname(_ context.Context) (string, error) {
	return f.hostName, nil
}

func (f fakeMetadataService) GetLabels(_ context.Context) (map[string]string, error) {
	return f.labels, nil
}

func (f fakeMetadataService) GetInstanceId(_ context.Context) (string, error) {
	return f.instanceID, nil
}

func (f fakeMetadataService) GetInternalIP(_ context.Context) (string, error) {
	return f.internalIP, nil
}

func (f fakeMetadataService) GetExternalIP(_ context.Context) (string, error) {
	return f.externalIP, nil
}

func (f fakeMetadataService) GetInternalDNS(_ context.Context) (string, error) {
	return f.internalDNS, nil
}

func (f fakeMetadataService) GetExternalDNS(_ context.Context) (string, error) {
	return f.externalDNS, nil
}

var defaultFakeMetadata = fakeMetadataService{
	hostName:    "ip-10-0-0-1.ec2.internal",
	labels:      map[string]string{"kubernetes.io/role": "1", "node.kubernetes.io/instance-type": "m5.large", "foo": "bar"},
	instanceID:  "i-0123456789abcdef0",
	internalIP:  "10.0.0.1",
	externalIP:  "34.0.0.1",
	internalDNS: "ip-10-0-0-1.ec2.internal",
	externalDNS: "ec2-34-0-0-1.compute-1.amazonaws.com",
}

var cmpIgnoreFields = []cmp.Option{
	cmpopts.IgnoreFields(metav1.Condition{}, "LastTransitionTime"),
	cmpopts.IgnoreFields(metav1.ObjectMeta{}, "ResourceVersion", "CreationTimestamp"),
}

func Test_desiredNode(t *testing.T) {
	type args struct {
		metadata local.MetadataService
	}
	tests := []struct {
		name    string
		args    args
		want    *v1alpha1.TetragonNode
		wantErr bool
	}{
		{
			name: "valid",
			args: args{
				metadata: defaultFakeMetadata,
			},
			want: &v1alpha1.TetragonNode{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ip-10-0-0-1.ec2.internal",
					Namespace: "default",
					Labels: map[string]string{
						"foo":                              "bar",
						"kubernetes.io/role":               "1",
						"node.kubernetes.io/instance-type": "m5.large",
					},
				},
				Status: v1alpha1.TetragonNodeStatus{
					Id:              "i-0123456789abcdef0",
					SoftwareVersion: version.Version,
					Addresses: []v1alpha1.NodeAddress{
						{
							Type: v1alpha1.NodeHostName,
							IP:   "ip-10-0-0-1.ec2.internal",
						},
						{
							Type: v1alpha1.NodeInternalIP,
							IP:   "10.0.0.1",
						},
						{
							Type: v1alpha1.NodeExternalIP,
							IP:   "34.0.0.1",
						},
						{
							Type: v1alpha1.NodeInternalDNS,
							IP:   "ip-10-0-0-1.ec2.internal",
						},

						{
							Type: v1alpha1.NodeExternalDNS,
							IP:   "ec2-34-0-0-1.compute-1.amazonaws.com",
						},
					},
					Conditions: []metav1.Condition{
						{
							Type:    "NodeRegistered",
							Status:  "True",
							Reason:  "NodeRegistered",
							Message: "Node successfully registered",
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := desiredNode(context.Background(), tt.args.metadata)
			require.True(t, (err != nil) == tt.wantErr)
			diff := cmp.Diff(tt.want, got, cmpIgnoreFields...)
			require.Empty(t, diff)
		})
	}
}

func Test_sanitizeLabels(t *testing.T) {
	type args struct {
		labels map[string]string
	}
	tests := []struct {
		name    string
		args    args
		valid   map[string]string
		invalid map[string]string
	}{
		{
			name: "valid labels",
			args: args{
				labels: map[string]string{
					"valid-label":            "value",
					"another.valid/label":    "value",
					"label.with_underscores": "value",
				},
			},
			valid: map[string]string{
				"valid-label":            "value",
				"another.valid/label":    "value",
				"label.with_underscores": "value",
			},
			invalid: map[string]string{},
		},
		{
			name: "invalid label name",
			args: args{
				labels: map[string]string{
					"valid-label":            "value",
					"k8s.io/level1/level2":   "value",
					"label.with_underscores": "value",
				},
			},
			valid: map[string]string{
				"valid-label":            "value",
				"label.with_underscores": "value",
			},
			invalid: map[string]string{
				"k8s.io/level1/level2": "value",
			},
		},
		{
			name: "valid label value",
			args: args{
				labels: map[string]string{
					"valid-label":            "invalid value",
					"another.valid/label":    "value",
					"label.with_underscores": "value",
				},
			},
			valid: map[string]string{
				"another.valid/label":    "value",
				"label.with_underscores": "value",
			},
			invalid: map[string]string{
				"valid-label": "invalid value",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, invalid := sanitizeLabels(tt.args.labels)
			require.Equal(t, tt.valid, valid)
			require.Equal(t, tt.invalid, invalid)
		})
	}
}
