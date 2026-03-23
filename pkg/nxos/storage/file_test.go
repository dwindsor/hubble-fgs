// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package storage

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/isovalent/hubble-fgs/pkg/nxos/types"
)

func TestFileStorage_VRFs(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	fs := NewFileStorage(WithStatesDir(tmpDir), WithVolatileDir(tmpDir))

	err := fs.EnsureReady(ctx)
	require.NoError(t, err)

	// Initially empty
	_, err = fs.LoadVRFs(ctx)
	require.Error(t, err)
	assert.True(t, IsNotFound(err))

	// Save some VRFs
	vrfs := map[string]types.VRF{
		"default":    {Name: "default", Global: true, GID: 1},
		"management": {Name: "management", Global: false, GID: 2},
	}
	err = fs.SaveVRFs(ctx, vrfs)
	require.NoError(t, err)

	// Verify file exists
	_, err = os.Stat(filepath.Join(tmpDir, vrfFileName))
	require.NoError(t, err)

	// Load and verify
	loaded, err := fs.LoadVRFs(ctx)
	require.NoError(t, err)
	assert.Len(t, loaded, 2)
	assert.Equal(t, "default", loaded["default"].Name)
	assert.True(t, loaded["default"].Global)
	assert.Equal(t, uint16(1), loaded["default"].GID)

	// Clear
	err = fs.Clear(ctx)
	require.NoError(t, err)

	_, err = os.Stat(filepath.Join(tmpDir, vrfFileName))
	assert.True(t, os.IsNotExist(err))
}

func TestFileStorage_VLANs(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	fs := NewFileStorage(WithStatesDir(tmpDir), WithVolatileDir(tmpDir))

	err := fs.EnsureReady(ctx)
	require.NoError(t, err)

	// Initially empty
	_, err = fs.LoadVLANs(ctx)
	require.Error(t, err)
	assert.True(t, IsNotFound(err))

	// Save some VLANs
	vlans := map[string]types.VLAN{
		"vlan10": {Name: "vlan10", Global: true, ID: 10},
		"vlan20": {Name: "vlan20", Service: true, ID: 20},
	}
	err = fs.SaveVLANs(ctx, vlans)
	require.NoError(t, err)

	// Verify file exists
	_, err = os.Stat(filepath.Join(tmpDir, vlanFileName))
	require.NoError(t, err)

	// Load and verify
	loaded, err := fs.LoadVLANs(ctx)
	require.NoError(t, err)
	assert.Len(t, loaded, 2)
	assert.Equal(t, "vlan10", loaded["vlan10"].Name)
	assert.True(t, loaded["vlan10"].Global)
	assert.Equal(t, uint16(10), loaded["vlan10"].ID)
}

func TestFileStorage_Device(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	fs := NewFileStorage(WithStatesDir(tmpDir), WithVolatileDir(tmpDir))

	err := fs.EnsureReady(ctx)
	require.NoError(t, err)

	// Initially empty
	_, err = fs.LoadDevice(ctx)
	require.Error(t, err)
	assert.True(t, IsNotFound(err))

	// Save device state
	state := &DeviceState{
		ProxyServer: "proxy.example.com",
		ProxyPort:   8080,
		LbMode:      "symmetric_hash",
	}
	err = fs.SaveDevice(ctx, state)
	require.NoError(t, err)

	// Verify file exists
	_, err = os.Stat(filepath.Join(tmpDir, deviceFileName))
	require.NoError(t, err)

	// Load and verify
	loaded, err := fs.LoadDevice(ctx)
	require.NoError(t, err)
	assert.Equal(t, "proxy.example.com", loaded.ProxyServer)
	assert.Equal(t, uint32(8080), loaded.ProxyPort)
	assert.Equal(t, "symmetric_hash", loaded.LbMode)
}

func TestFileStorage_HA(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	fs := NewFileStorage(WithStatesDir(tmpDir), WithVolatileDir(tmpDir))

	err := fs.EnsureReady(ctx)
	require.NoError(t, err)

	// Initially empty
	_, err = fs.LoadHA(ctx)
	require.Error(t, err)
	assert.True(t, IsNotFound(err))

	// Save HA state
	state := &HAState{
		Enabled: "enabled",
		HaIP:    "10.0.0.1",
		PeerIPs: []string{"192.168.1.2", "192.168.1.3"},
	}
	err = fs.SaveHA(ctx, state)
	require.NoError(t, err)

	// Verify file exists
	_, err = os.Stat(filepath.Join(tmpDir, haFileName))
	require.NoError(t, err)

	// Load and verify
	loaded, err := fs.LoadHA(ctx)
	require.NoError(t, err)
	assert.Equal(t, "enabled", loaded.Enabled)
	assert.Equal(t, "10.0.0.1", loaded.HaIP)
	assert.ElementsMatch(t, []string{"192.168.1.2", "192.168.1.3"}, loaded.PeerIPs)
}

func TestFileStorage_Persistence(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	// Create first storage instance and save data
	fs1 := NewFileStorage(WithStatesDir(tmpDir), WithVolatileDir(tmpDir))
	err := fs1.EnsureReady(ctx)
	require.NoError(t, err)

	vrfs := map[string]types.VRF{
		"test": {Name: "test", GID: 42, Global: true},
	}
	err = fs1.SaveVRFs(ctx, vrfs)
	require.NoError(t, err)

	// Create second storage instance and verify data persisted
	fs2 := NewFileStorage(WithStatesDir(tmpDir), WithVolatileDir(tmpDir))

	loaded, err := fs2.LoadVRFs(ctx)
	require.NoError(t, err)
	assert.Len(t, loaded, 1)
	assert.Equal(t, "test", loaded["test"].Name)
	assert.Equal(t, uint16(42), loaded["test"].GID)
	assert.True(t, loaded["test"].Global)
}
