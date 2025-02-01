package model

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/isovalent/ipa/application_model/v1alpha"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestEnsureSorted(t *testing.T) {
	model := &v1alpha.ApplicationModel{
		Namespaces: []*v1alpha.ApplicationNamespace{{Name: "b"}, {Name: "a"}, {Name: "c"}},
		Host: &v1alpha.ApplicationHost{
			Processes: []*v1alpha.ApplicationProcessGroup{
				{
					Name: "b",
				},
				{
					Name: "a",
					Connections: []*v1alpha.ApplicationConnection{
						{
							DestinationName: "b.com",
						},
						{
							DestinationName: "a.com",
						},
					},
				},
				{
					Name: "c",
				},
			},
		},
	}
	sortedModel := &v1alpha.ApplicationModel{
		Namespaces: []*v1alpha.ApplicationNamespace{{Name: "a"}, {Name: "b"}, {Name: "c"}},
		Host: &v1alpha.ApplicationHost{
			Processes: []*v1alpha.ApplicationProcessGroup{
				{
					Name: "a",
					Connections: []*v1alpha.ApplicationConnection{
						{
							DestinationName: "a.com",
						},
						{
							DestinationName: "b.com",
						},
					},
				},
				{
					Name: "b",
				},
				{
					Name: "c",
				},
			},
		},
	}
	require.NotEmpty(t, cmp.Diff(model, sortedModel, protocmp.Transform()))
	EnsureSorted(model)
	assert.Empty(t, cmp.Diff(model, sortedModel, protocmp.Transform()))
}
