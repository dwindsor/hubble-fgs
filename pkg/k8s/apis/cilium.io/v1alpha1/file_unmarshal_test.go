// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.
package v1alpha1

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileSpecUnmarshalJSON(t *testing.T) {
	t.Run("rejects unknown selector field", func(t *testing.T) {
		data := `{
			"file_paths_patterns": [{"type": "AllFileOps"}],
			"selectors": [{"matchSomething": [{"value": "123"}]}]
		}`
		var spec FileSpec
		err := json.Unmarshal([]byte(data), &spec)
		require.Error(t, err)
		require.Contains(t, err.Error(), "json: unknown field \"matchSomething\"")
	})

	t.Run("rejects unknown top-level field", func(t *testing.T) {
		data := `{"file_paths_patterns": [{"type": "AllFileOps"}], "bogus": true}`
		var spec FileSpec
		require.Error(t, json.Unmarshal([]byte(data), &spec))
	})

	t.Run("accepts valid spec and defaults MonitorHostFiles", func(t *testing.T) {
		data := `{
			"file_paths_patterns": [{"type": "AllFileOps"}],
			"selectors": [{
				"matchNamespaces": [{"namespace": "Mnt", "operator": "In", "values": [ "1" ]}],
				"matchActions": [{"action": "Post"}]
			}]
		}`
		var spec FileSpec
		require.NoError(t, json.Unmarshal([]byte(data), &spec))
		assert.True(t, spec.MonitorHostFiles, "MonitorHostFiles should default to true")
		require.Len(t, spec.Selectors, 1)
		require.Len(t, spec.Selectors[0].MatchNamespacesOSS, 1)
		assert.Equal(t, "In", spec.Selectors[0].MatchNamespacesOSS[0].Operator)
		assert.Equal(t, "Mnt", spec.Selectors[0].MatchNamespacesOSS[0].Namespace)
		assert.Equal(t, []string{"1"}, spec.Selectors[0].MatchNamespacesOSS[0].Values)
	})

	t.Run("accepts valid spec and defaults MonitorHostFiles", func(t *testing.T) {
		data := `{
			"file_paths_patterns": [{"type": "AllFileOps"}],
			"selectors": [{
				"matchLinuxNamespaces": [{"namespace": "Mnt", "filter": "NoHost"}],
				"matchActions": [{"action": "Post"}]
			}]
		}`
		var spec FileSpec
		require.NoError(t, json.Unmarshal([]byte(data), &spec))
		assert.True(t, spec.MonitorHostFiles, "MonitorHostFiles should default to true")
		require.Len(t, spec.Selectors, 1)
		require.Len(t, spec.Selectors[0].MatchNamespaces, 1)
		assert.Equal(t, "Mnt", spec.Selectors[0].MatchNamespaces[0].Namespace)
		assert.Equal(t, "NoHost", spec.Selectors[0].MatchNamespaces[0].Filter)
	})

	t.Run("explicit MonitorHostFiles=false is preserved", func(t *testing.T) {
		data := `{"file_paths_patterns": [{"type": "AllFileOps"}], "monitorHostFiles": false}`
		var spec FileSpec
		require.NoError(t, json.Unmarshal([]byte(data), &spec))
		assert.False(t, spec.MonitorHostFiles)
	})
}
