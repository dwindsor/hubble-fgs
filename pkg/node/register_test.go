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

package node

import (
	"context"
	"testing"

	"github.com/cilium/tetragon/pkg/version"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/isovalent/ipa/k8s/apis/isovalent.com/v1alpha1"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

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

type fakeKubernetesMetadataService struct {
	fakeMetadataService
	node *corev1.Node
}

func (f fakeKubernetesMetadataService) GetKubernetesNode(_ context.Context) (*corev1.Node, error) {
	return f.node, nil
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
			got, err := desiredNode(t.Context(), tt.args.metadata)
			require.True(t, (err != nil) == tt.wantErr)
			diff := cmp.Diff(tt.want, got, cmpIgnoreFields...)
			require.Empty(t, diff)
		})
	}
}

func TestRegisterAddsKubernetesNodeOwnerReference(t *testing.T) {
	ownerNode := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-node",
			UID:  types.UID("test-node-uid"),
		},
	}
	metadata := fakeKubernetesMetadataService{
		fakeMetadataService: fakeMetadataService{
			hostName:   ownerNode.Name,
			labels:     map[string]string{"foo": "bar"},
			instanceID: ownerNode.Name,
			internalIP: "10.0.0.1",
		},
		node: ownerNode,
	}
	scheme, client := newRegisterTestClient(t)
	registerer := &registerer{
		metadata: metadata,
		client:   client,
		scheme:   scheme,
	}

	require.NoError(t, registerer.Register(t.Context()))

	got := requireTetragonNode(t, client, "default", ownerNode.Name)
	requireNodeOwnerReference(t, got, ownerNode)
}

func TestRegisterAddsMissingKubernetesNodeOwnerReference(t *testing.T) {
	ownerNode := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-node",
			UID:  types.UID("test-node-uid"),
		},
	}
	existing := &v1alpha1.TetragonNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ownerNode.Name,
			Namespace: "default",
			Labels:    map[string]string{"old": "label"},
		},
	}
	metadata := fakeKubernetesMetadataService{
		fakeMetadataService: fakeMetadataService{
			hostName:   ownerNode.Name,
			labels:     map[string]string{"foo": "bar"},
			instanceID: ownerNode.Name,
			internalIP: "10.0.0.1",
		},
		node: ownerNode,
	}
	scheme, client := newRegisterTestClient(t, existing)
	registerer := &registerer{
		metadata: metadata,
		client:   client,
		scheme:   scheme,
	}

	require.NoError(t, registerer.Register(t.Context()))

	got := requireTetragonNode(t, client, "default", ownerNode.Name)
	requireNodeOwnerReference(t, got, ownerNode)
	require.Equal(t, map[string]string{"foo": "bar"}, got.Labels)
}

func TestRegisterDoesNotAddOwnerReferenceForNonKubernetesMetadata(t *testing.T) {
	ctx := t.Context()
	scheme, client := newRegisterTestClient(t)
	registerer := &registerer{
		metadata: defaultFakeMetadata,
		client:   client,
		scheme:   scheme,
	}

	require.NoError(t, registerer.Register(ctx))

	got := requireTetragonNode(t, client, "default", defaultFakeMetadata.hostName)
	require.Empty(t, got.OwnerReferences)
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

func newRegisterTestClient(t *testing.T, initObjs ...k8sclient.Object) (*runtime.Scheme, k8sclient.Client) {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))
	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.TetragonNode{}).
		WithObjects(initObjs...).
		Build()
	return scheme, client
}

func requireTetragonNode(t *testing.T, client k8sclient.Client, namespace, name string) *v1alpha1.TetragonNode {
	t.Helper()

	node := &v1alpha1.TetragonNode{}
	require.NoError(t, client.Get(t.Context(), k8sclient.ObjectKey{
		Namespace: namespace,
		Name:      name,
	}, node))
	return node
}

func requireNodeOwnerReference(t *testing.T, tetragonNode *v1alpha1.TetragonNode, ownerNode *corev1.Node) {
	t.Helper()

	require.Len(t, tetragonNode.OwnerReferences, 1)
	ref := tetragonNode.OwnerReferences[0]
	require.Equal(t, "v1", ref.APIVersion)
	require.Equal(t, "Node", ref.Kind)
	require.Equal(t, ownerNode.Name, ref.Name)
	require.Equal(t, ownerNode.UID, ref.UID)
	require.Nil(t, ref.Controller)
	require.Nil(t, ref.BlockOwnerDeletion)
}
