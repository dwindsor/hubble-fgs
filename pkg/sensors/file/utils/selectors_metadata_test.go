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
// ./go-tests/file-utils.test -test.run TestGetSelectorsMetadata1

package file

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

func TestGetSelectorsMetadata1(t *testing.T) {
	o, err := GetSelectorsMetadata([]v1alpha1.FileSelector{
		{
			MatchOperations: []v1alpha1.OperationSelector{
				{
					Operator: "In",
					Values: []string{
						"FILE_OPEN",
						"FILE_OPENRAW",
					},
				},
			},
		},
	})
	assert.NoError(t, err)
	assert.True(t, o.HasMatchOperations)
	assert.Equal(t, o.OperationsSet, NewSet([]tetragon.FileAction{tetragon.FileAction_FILE_OPEN, tetragon.FileAction_FILE_OPENRAW}...))
}

func TestGetSelectorsMetadata2(t *testing.T) {
	o, err := GetSelectorsMetadata([]v1alpha1.FileSelector{
		{
			MatchOperations: []v1alpha1.OperationSelector{
				{
					Operator: "In",
					Values: []string{
						"FILE_READ",
					},
				},
			},
		},
		{
			MatchOperations: []v1alpha1.OperationSelector{
				{
					Operator: "In",
					Values: []string{
						"FILE_WRITE",
					},
				},
			},
		},
	})
	assert.NoError(t, err)
	assert.True(t, o.HasMatchOperations)
	assert.Equal(t, o.OperationsSet, NewSet([]tetragon.FileAction{tetragon.FileAction_FILE_READ, tetragon.FileAction_FILE_WRITE}...))
}

func TestGetSelectorsMetadata3(t *testing.T) {
	o, err := GetSelectorsMetadata([]v1alpha1.FileSelector{
		{
			MatchOperations: []v1alpha1.OperationSelector{
				{
					Operator: "NotIn",
					Values: []string{
						"FILE_OPEN",
					},
				},
			},
		},
	})
	assert.NoError(t, err)
	assert.True(t, o.HasMatchOperations)
	assert.Equal(t, o.OperationsSet, NewSet(getAllOps()...).Difference(NewSet([]tetragon.FileAction{tetragon.FileAction_FILE_OPEN}...)))
}

func TestGetSelectorsMetadata4(t *testing.T) {
	o, err := GetSelectorsMetadata([]v1alpha1.FileSelector{
		{
			MatchOperations: []v1alpha1.OperationSelector{
				{
					Operator: "NotIn",
					Values: []string{
						"FILE_READ",
					},
				},
			},
		},
		{
			MatchOperations: []v1alpha1.OperationSelector{
				{
					Operator: "In",
					Values: []string{
						"FILE_READ",
					},
				},
			},
		},
	})
	assert.NoError(t, err)
	assert.True(t, o.HasMatchOperations)
	assert.Equal(t, o.OperationsSet, NewSet(getAllOps()...))
}

func TestGetSelectorsMetadata5(t *testing.T) {
	o, err := GetSelectorsMetadata(nil)
	assert.NoError(t, err)
	assert.False(t, o.HasMatchOperations)
	assert.Equal(t, o.OperationsSet, NewSet(getAllOps()...))
}

func TestGetSelectorsMetadata6(t *testing.T) {
	o, err := GetSelectorsMetadata([]v1alpha1.FileSelector{})
	assert.NoError(t, err)
	assert.False(t, o.HasMatchOperations)
	assert.Equal(t, o.OperationsSet, NewSet(getAllOps()...))
}

func TestGetSelectorsMetadata7(t *testing.T) {
	o, err := GetSelectorsMetadata([]v1alpha1.FileSelector{
		{
			MatchFilename: []v1alpha1.FilePathGlobSelector{
				{
					Operator: "InFileWithDigest",
					Values: []v1alpha1.GlobPattern{
						"/usr/bin/touch",
					},
				},
			},
		},
		{
			MatchFilename: []v1alpha1.FilePathGlobSelector{
				{
					Operator: "InFileWithDigest",
					Values: []v1alpha1.GlobPattern{
						"/usr/bin/touch",
					},
				},
			},
		},
		{
			MatchBinaries: []v1alpha1.BinarySelector{{
				Operator: "In",
				Values: []string{
					"/usr/bin/cat",
				},
				FollowChildren: true,
			}},
		},
	})
	assert.NoError(t, err)
	assert.True(t, o.HasMatchBinaries)
	assert.True(t, o.HasMatchFilename)
	assert.Equal(t, o.OperationsSet, NewSet(getAllOps()...))
}

func TestGetSelectorsMetadata8(t *testing.T) {
	o, err := GetSelectorsMetadata([]v1alpha1.FileSelector{
		{
			MatchFilename: []v1alpha1.FilePathGlobSelector{
				{
					Operator: "InFileWithDigest",
					Values: []v1alpha1.GlobPattern{
						"/usr/bin/touch",
					},
				},
			},
		},
		{
			MatchFilename: []v1alpha1.FilePathGlobSelector{
				{
					Operator: "InFileWithDigest",
					Values: []v1alpha1.GlobPattern{
						"/usr/bin/touch",
					},
				},
			},
		},
		{
			MatchBinaries: []v1alpha1.BinarySelector{{
				Operator: "In",
				Values: []string{
					"/usr/bin/cat",
				},
				FollowChildren: true,
			}},
			MatchOperations: []v1alpha1.OperationSelector{
				{
					Operator: "In",
					Values: []string{
						"FILE_EXEC",
					},
				},
			},
		},
	})
	assert.NoError(t, err)
	assert.True(t, o.HasMatchBinaries)
	assert.True(t, o.HasMatchFilename)
	assert.True(t, o.HasMatchOperations)
	assert.Equal(t, o.OperationsSet, NewSet(getAllOps()...))
}

func TestGetSelectorsMetadataMatchCapabilities(t *testing.T) {
	o, err := GetSelectorsMetadata([]v1alpha1.FileSelector{
		{
			MatchCapabilitiesOSS: []v1alpha1.CapabilitiesSelector{
				{
					Operator: "In",
					Values:   []string{"CAP_SYS_ADMIN"},
				},
			},
		},
	})
	assert.NoError(t, err)
	assert.True(t, o.HasMatchCapabilities)
}

func TestGetSelectorsMetadataMatchNamespaces(t *testing.T) {
	o, err := GetSelectorsMetadata([]v1alpha1.FileSelector{
		{
			MatchNamespacesOSS: []v1alpha1.NamespaceSelector{
				{
					Namespace: "Mnt",
					Operator:  "In",
					Values: []string{
						"host_ns",
					},
				},
			},
		},
	})
	assert.NoError(t, err)
	assert.True(t, o.HasMatchNamespaces)
}
