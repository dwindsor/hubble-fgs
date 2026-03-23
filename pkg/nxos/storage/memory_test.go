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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/isovalent/hubble-fgs/pkg/nxos/types"
)

func TestMemoryStorage_VRFs(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStorage()

	// Initially empty
	_, err := ms.LoadVRFs(ctx)
	require.Error(t, err)
	assert.True(t, IsNotFound(err))

	// Save some VRFs
	vrfs := map[string]types.VRF{
		"default":    {Name: "default", Global: true, GID: 1},
		"management": {Name: "management", Global: true, GID: 2},
	}
	err = ms.SaveVRFs(ctx, vrfs)
	require.NoError(t, err)

	// Load and verify
	loaded, err := ms.LoadVRFs(ctx)
	require.NoError(t, err)
	assert.Len(t, loaded, 2)
	assert.Equal(t, "default", loaded["default"].Name)
	assert.Equal(t, uint16(1), loaded["default"].GID)

	// Clear
	err = ms.Clear(ctx)
	require.NoError(t, err)

	_, err = ms.LoadVRFs(ctx)
	assert.True(t, IsNotFound(err))
}

func TestMemoryStorage_VLANs(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStorage()

	// Initially empty
	_, err := ms.LoadVLANs(ctx)
	require.Error(t, err)
	assert.True(t, IsNotFound(err))

	// Save some VLANs
	vlans := map[string]types.VLAN{
		"vlan10": {Name: "vlan10", Global: true, ID: 10},
		"vlan20": {Name: "vlan20", Global: true, ID: 20},
	}
	err = ms.SaveVLANs(ctx, vlans)
	require.NoError(t, err)

	// Load and verify
	loaded, err := ms.LoadVLANs(ctx)
	require.NoError(t, err)
	assert.Len(t, loaded, 2)
	assert.Equal(t, "vlan10", loaded["vlan10"].Name)
	assert.Equal(t, uint16(10), loaded["vlan10"].ID)

	// Clear
	err = ms.Clear(ctx)
	require.NoError(t, err)

	_, err = ms.LoadVLANs(ctx)
	assert.True(t, IsNotFound(err))
}

func TestMemoryStorage_Device(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStorage()

	// Initially empty
	_, err := ms.LoadDevice(ctx)
	require.Error(t, err)
	assert.True(t, IsNotFound(err))

	// Save device state
	state := &DeviceState{
		ProxyServer:   "proxy.example.com",
		ProxyPort:     8080,
		ServiceIP:     "192.168.1.1",
		SkipReg:       false,
		SkipRegReason: "",
		LbMode:        "symmetric_hash",
	}
	err = ms.SaveDevice(ctx, state)
	require.NoError(t, err)

	// Load and verify
	loaded, err := ms.LoadDevice(ctx)
	require.NoError(t, err)
	assert.Equal(t, "proxy.example.com", loaded.ProxyServer)
	assert.Equal(t, uint32(8080), loaded.ProxyPort)
	assert.Equal(t, "192.168.1.1", loaded.ServiceIP)
	assert.Equal(t, "symmetric_hash", loaded.LbMode)

	// Clear
	err = ms.Clear(ctx)
	require.NoError(t, err)

	_, err = ms.LoadDevice(ctx)
	assert.True(t, IsNotFound(err))
}

func TestMemoryStorage_HA(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStorage()

	// Initially empty
	_, err := ms.LoadHA(ctx)
	require.Error(t, err)
	assert.True(t, IsNotFound(err))

	// Save HA state
	state := &HAState{
		Enabled: "enabled",
		HaIP:    "10.0.0.1",
		PeerIPs: []string{"10.0.0.2", "10.0.0.3"},
	}
	err = ms.SaveHA(ctx, state)
	require.NoError(t, err)

	// Load and verify — only config fields and peer IPs are persisted
	loaded, err := ms.LoadHA(ctx)
	require.NoError(t, err)
	assert.Equal(t, "enabled", loaded.Enabled)
	assert.Equal(t, "10.0.0.1", loaded.HaIP)
	assert.ElementsMatch(t, []string{"10.0.0.2", "10.0.0.3"}, loaded.PeerIPs)

	// Clear
	err = ms.Clear(ctx)
	require.NoError(t, err)

	_, err = ms.LoadHA(ctx)
	assert.True(t, IsNotFound(err))
}

func TestMemoryStorage_DataIsolation(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStorage()

	// Save VRFs
	vrfs := map[string]types.VRF{
		"test": {Name: "test", GID: 1},
	}
	err := ms.SaveVRFs(ctx, vrfs)
	require.NoError(t, err)

	// Modify original map
	vrfs["test"] = types.VRF{Name: "modified", GID: 99}

	// Load should return original values (storage made a copy)
	loaded, err := ms.LoadVRFs(ctx)
	require.NoError(t, err)
	assert.Equal(t, uint16(1), loaded["test"].GID)
}
