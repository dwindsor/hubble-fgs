// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package switchpolicy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDiff(t *testing.T) {
	t.Run("added VRF", func(t *testing.T) {
		current := NewL3Networks()
		require.NoError(t, current.Add("red", 100))

		incoming := NewL3Networks()
		require.NoError(t, incoming.Add("red", 100))
		require.NoError(t, incoming.Add("blue", 200))

		added, removed, changed := current.Diff(incoming)

		require.Equal(t, map[VrfName]VrfGID{"blue": 200}, added)
		require.Empty(t, removed)
		require.Empty(t, changed)
	})

	t.Run("removed VRF", func(t *testing.T) {
		current := NewL3Networks()
		require.NoError(t, current.Add("red", 100))
		require.NoError(t, current.Add("blue", 200))

		incoming := NewL3Networks()
		require.NoError(t, incoming.Add("red", 100))

		added, removed, changed := current.Diff(incoming)

		require.Empty(t, added)
		require.Equal(t, map[VrfName]VrfGID{"blue": 200}, removed)
		require.Empty(t, changed)
	})

	t.Run("changed GID", func(t *testing.T) {
		current := NewL3Networks()
		require.NoError(t, current.Add("red", 100))

		incoming := NewL3Networks()
		require.NoError(t, incoming.Add("red", 200))

		added, removed, changed := current.Diff(incoming)

		require.Empty(t, added)
		require.Empty(t, removed)
		require.Equal(t, map[VrfName]GIDChange{"red": {OldGID: 100, NewGID: 200}}, changed)
	})

	t.Run("GID swap", func(t *testing.T) {
		current := NewL3Networks()
		require.NoError(t, current.Add("red", 100))
		require.NoError(t, current.Add("blue", 200))

		incoming := NewL3Networks()
		require.NoError(t, incoming.Add("red", 200))
		require.NoError(t, incoming.Add("blue", 100))

		added, removed, changed := current.Diff(incoming)

		require.Empty(t, added)
		require.Empty(t, removed)
		require.Equal(t, GIDChange{OldGID: 100, NewGID: 200}, changed["red"])
		require.Equal(t, GIDChange{OldGID: 200, NewGID: 100}, changed["blue"])
	})

	t.Run("no changes", func(t *testing.T) {
		current := NewL3Networks()
		require.NoError(t, current.Add("red", 100))

		incoming := NewL3Networks()
		require.NoError(t, incoming.Add("red", 100))

		added, removed, changed := current.Diff(incoming)

		require.Empty(t, added)
		require.Empty(t, removed)
		require.Empty(t, changed)
	})
}

// TestL3Networks_AddVrfWithGID0 verifies that VRFs with global ID 0 are handled correctly.
// Since NewL3Networks initializes with empty string ("") mapped to GID 0, attempting to add
// another VRF with GID 0 should fail.
func TestL3Networks_AddVrfWithGID0(t *testing.T) {
	l3 := NewL3Networks()

	// Verify initial state: empty string should be mapped to GID 0
	if gid, ok := l3.byName[""]; !ok || gid != 0 {
		t.Errorf("Expected empty string to be mapped to GID 0, got ok=%v, gid=%d", ok, gid)
	}
	if name, ok := l3.byGID[0]; !ok || name != "" {
		t.Errorf("Expected GID 0 to be mapped to empty string, got ok=%v, name=%q", ok, name)
	}

	// Test 1: Attempt to add a VRF with GID 0 but different name (should fail)
	err := l3.Add("test-vrf", 0)
	if err == nil {
		t.Error("Expected error when adding VRF with duplicate GID 0, got nil")
	}

	// Verify the error message
	expectedErr := "L3 network VRF  with GID 0 already exists"
	if err != nil && err.Error() != expectedErr {
		t.Errorf("Expected error message %q, got %q", expectedErr, err.Error())
	}

	// Verify that the original mapping is unchanged
	if gid, ok := l3.byName[""]; !ok || gid != 0 {
		t.Errorf("Original mapping corrupted: empty string should still map to GID 0, got ok=%v, gid=%d", ok, gid)
	}
	if _, ok := l3.byName["test-vrf"]; ok {
		t.Error("VRF 'test-vrf' should not have been added")
	}

	// Test 2: Attempt to add a VRF with empty string name but different GID (should fail)
	err = l3.Add("", 100)
	if err == nil {
		t.Error("Expected error when adding VRF with duplicate empty string name, got nil")
	}

	// Verify the error message
	expectedErr = "L3 network with name  already exists"
	if err != nil && err.Error() != expectedErr {
		t.Errorf("Expected error message %q, got %q", expectedErr, err.Error())
	}

	// Verify that GID 100 was not added
	if _, ok := l3.byGID[100]; ok {
		t.Error("GID 100 should not have been added")
	}

	// Test 3: Verify we can still add VRFs with non-zero GIDs
	err = l3.Add("valid-vrf", 1)
	if err != nil {
		t.Errorf("Expected no error when adding valid VRF, got %v", err)
	}

	// Verify the valid VRF was added correctly
	if gid, ok := l3.byName["valid-vrf"]; !ok || gid != 1 {
		t.Errorf("Expected 'valid-vrf' to be mapped to GID 1, got ok=%v, gid=%d", ok, gid)
	}
	if name, ok := l3.byGID[1]; !ok || name != "valid-vrf" {
		t.Errorf("Expected GID 1 to be mapped to 'valid-vrf', got ok=%v, name=%q", ok, name)
	}
}
