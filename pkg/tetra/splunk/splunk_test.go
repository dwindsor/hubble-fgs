// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package splunk

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	splunkV1 "github.com/isovalent/ipa/splunk/v1alpha"
)

func TestHECSetPrintsUsageWithoutOptions(t *testing.T) {
	cmd := newHECSetCommand()
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&output)

	require.NoError(t, cmd.Execute())
	require.Contains(t, output.String(), "Usage:")
}

func TestMergeHecSettings(t *testing.T) {
	current := &splunkV1.GetHecSettingsResponse{
		Endpoint:    "https://splunk.example.com:8088",
		Token:       "old-token",
		SourceTypes: []string{"tetragon:events"},
	}

	settings := mergeHecSettings(current, "", "new-token", nil, false, true, false)

	require.Equal(t, "https://splunk.example.com:8088", settings.Endpoint)
	require.Equal(t, "new-token", settings.Token)
	require.Equal(t, []string{"tetragon:events"}, settings.SourceTypes)

	settings.SourceTypes[0] = "changed"
	require.Equal(t, []string{"tetragon:events"}, current.SourceTypes)
}

func TestMergeHecSettingsWithChangedValues(t *testing.T) {
	settings := mergeHecSettings(
		&splunkV1.GetHecSettingsResponse{Endpoint: "old", Token: "old", SourceTypes: []string{"old"}},
		"new",
		"new-token",
		[]string{"new-source"},
		true,
		true,
		true,
	)

	require.Equal(t, &splunkV1.SetHecSettingsRequest{
		Endpoint:    "new",
		Token:       "new-token",
		SourceTypes: []string{"new-source"},
	}, settings)
}
