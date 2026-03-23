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
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"

	"github.com/isovalent/hubble-fgs/pkg/nxos/types"
)

// Default paths for persistence.
const (
	DefaultRootPath     = "/iox_data"
	DefaultStatesPath   = "/iox_data/states"
	DefaultVolatilePath = "/data/volatile"
	vrfFileName         = "vrf_store.json"
	vlanFileName        = "vlan_store.json"
	deviceFileName      = "device.json"
	haFileName          = "ha.json"
	dpuFileName         = "dpu_store.json"
)

// persistedVRFState represents the persisted VRF store state.
type persistedVRFState struct {
	VRFs map[string]types.VRF `json:"vrfs"`
}

// persistedVLANState represents the persisted VLAN store state.
type persistedVLANState struct {
	VLANs map[string]types.VLAN `json:"vlans"`
}

// persistedDPUState represents the persisted DPU store state.
type persistedDPUState struct {
	DPUs map[string]types.DPU `json:"dpus"`
}

// FileStorage implements Storage using the filesystem.
type FileStorage struct {
	mu          sync.RWMutex
	statesDir   string
	volatileDir string
}

// FileStorageOption configures FileStorage.
type FileStorageOption func(*FileStorage)

// WithStatesDir sets the directory for state files.
func WithStatesDir(dir string) FileStorageOption {
	return func(fs *FileStorage) {
		fs.statesDir = dir
	}
}

// WithVolatileDir sets the directory for volatile files.
func WithVolatileDir(dir string) FileStorageOption {
	return func(fs *FileStorage) {
		fs.volatileDir = dir
	}
}

// NewFileStorage creates a new FileStorage with the given options.
func NewFileStorage(opts ...FileStorageOption) *FileStorage {
	fs := &FileStorage{
		statesDir:   DefaultStatesPath,
		volatileDir: DefaultVolatilePath,
	}
	for _, opt := range opts {
		opt(fs)
	}
	return fs
}

// EnsureReady creates the storage directories if they don't exist.
func (fs *FileStorage) EnsureReady(ctx context.Context) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if err := os.MkdirAll(fs.statesDir, 0755); err != nil {
		logger.GetLogger().Error("Failed to create storage directory", logfields.Error, err, "path", fs.statesDir)
		return err
	}
	logger.GetLogger().Debug("Storage directory ready", "path", fs.statesDir)

	if err := os.MkdirAll(fs.volatileDir, 0755); err != nil {
		logger.GetLogger().Error("Failed to create volatile directory", logfields.Error, err, "path", fs.volatileDir)
		return err
	}
	logger.GetLogger().Debug("Volatile directory ready", "path", fs.volatileDir)
	return nil
}

// LoadVRFs loads VRF data from the filesystem.
func (fs *FileStorage) LoadVRFs(ctx context.Context) (map[string]types.VRF, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	path := filepath.Join(fs.statesDir, vrfFileName)
	var state persistedVRFState
	if err := fs.loadFile(path, &state); err != nil {
		if os.IsNotExist(err) {
			logger.GetLogger().Debug("VRF store file not found, starting fresh", "path", path)
			return nil, &ErrNotFound{Key: "vrfs"}
		}
		return nil, err
	}
	logger.GetLogger().Info("Loaded VRFs from storage", "count", len(state.VRFs))
	return state.VRFs, nil
}

// SaveVRFs saves VRF data to the filesystem.
func (fs *FileStorage) SaveVRFs(ctx context.Context, vrfs map[string]types.VRF) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	path := filepath.Join(fs.statesDir, vrfFileName)
	state := persistedVRFState{VRFs: vrfs}
	if err := fs.saveFile(path, state); err != nil {
		return err
	}
	logger.GetLogger().Debug("Saved VRFs to storage", "count", len(vrfs))
	return nil
}

// LoadVLANs loads VLAN data from the filesystem.
func (fs *FileStorage) LoadVLANs(ctx context.Context) (map[string]types.VLAN, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	path := filepath.Join(fs.statesDir, vlanFileName)
	var state persistedVLANState
	if err := fs.loadFile(path, &state); err != nil {
		if os.IsNotExist(err) {
			logger.GetLogger().Debug("VLAN store file not found, starting fresh", "path", path)
			return nil, &ErrNotFound{Key: "vlans"}
		}
		return nil, err
	}
	logger.GetLogger().Info("Loaded VLANs from storage", "count", len(state.VLANs))
	return state.VLANs, nil
}

// SaveVLANs saves VLAN data to the filesystem.
func (fs *FileStorage) SaveVLANs(ctx context.Context, vlans map[string]types.VLAN) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	path := filepath.Join(fs.statesDir, vlanFileName)
	state := persistedVLANState{VLANs: vlans}
	if err := fs.saveFile(path, state); err != nil {
		return err
	}
	logger.GetLogger().Debug("Saved VLANs to storage", "count", len(vlans))
	return nil
}

// LoadDevice loads device state from the filesystem.
func (fs *FileStorage) LoadDevice(ctx context.Context) (*DeviceState, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	path := filepath.Join(fs.statesDir, deviceFileName)
	var state DeviceState
	if err := fs.loadFile(path, &state); err != nil {
		if os.IsNotExist(err) {
			logger.GetLogger().Debug("Device store file not found, starting fresh", "path", path)
			return nil, &ErrNotFound{Key: "device"}
		}
		return nil, err
	}
	logger.GetLogger().Info("Loaded device state from storage")
	return &state, nil
}

// SaveDevice saves device state to the filesystem.
func (fs *FileStorage) SaveDevice(ctx context.Context, state *DeviceState) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	path := filepath.Join(fs.statesDir, deviceFileName)
	if err := fs.saveFile(path, state); err != nil {
		return err
	}
	logger.GetLogger().Debug("Saved device state to storage")
	return nil
}

// LoadHA loads HA state from the filesystem.
func (fs *FileStorage) LoadHA(ctx context.Context) (*HAState, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	path := filepath.Join(fs.statesDir, haFileName)
	var state HAState
	if err := fs.loadFile(path, &state); err != nil {
		if os.IsNotExist(err) {
			logger.GetLogger().Debug("HA store file not found, starting fresh", "path", path)
			return nil, &ErrNotFound{Key: "ha"}
		}
		return nil, err
	}
	logger.GetLogger().Info("Loaded HA state from storage")
	return &state, nil
}

// SaveHA saves HA state to the filesystem.
func (fs *FileStorage) SaveHA(ctx context.Context, state *HAState) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	path := filepath.Join(fs.statesDir, haFileName)
	if err := fs.saveFile(path, state); err != nil {
		return err
	}
	logger.GetLogger().Debug("Saved HA state to storage")
	return nil
}

// LoadDPUs loads DPU data from the filesystem.
func (fs *FileStorage) LoadDPUs(ctx context.Context) (map[string]types.DPU, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	path := filepath.Join(fs.volatileDir, dpuFileName)
	var state persistedDPUState
	if err := fs.loadFile(path, &state); err != nil {
		if os.IsNotExist(err) {
			logger.GetLogger().Debug("DPU store file not found, starting fresh", "path", path)
			return nil, &ErrNotFound{Key: "dpus"}
		}
		return nil, err
	}
	logger.GetLogger().Info("Loaded DPUs from storage", "count", len(state.DPUs))
	return state.DPUs, nil
}

// SaveDPUs saves DPU data to the filesystem.
func (fs *FileStorage) SaveDPUs(ctx context.Context, dpus map[string]types.DPU) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	path := filepath.Join(fs.volatileDir, dpuFileName)
	state := persistedDPUState{DPUs: dpus}
	if err := fs.saveFile(path, state); err != nil {
		return err
	}
	logger.GetLogger().Debug("Saved DPUs to storage", "count", len(dpus))
	return nil
}

// Clear removes all persisted data.
func (fs *FileStorage) Clear(ctx context.Context) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	files := []struct {
		dir  string
		name string
	}{
		{fs.statesDir, vrfFileName},
		{fs.statesDir, vlanFileName},
		{fs.statesDir, deviceFileName},
		{fs.statesDir, haFileName},
		{fs.volatileDir, dpuFileName},
	}

	var lastErr error
	for _, f := range files {
		path := filepath.Join(f.dir, f.name)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			logger.GetLogger().Error("Failed to remove store file", logfields.Error, err, "path", path)
			lastErr = err
		}
	}
	return lastErr
}

// loadFile reads and unmarshals JSON data from a file.
func (fs *FileStorage) loadFile(path string, content any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, content); err != nil {
		logger.GetLogger().Error("Failed to unmarshal storage file", logfields.Error, err, "path", path)
		return err
	}
	return nil
}

// saveFile marshals and writes JSON data to a file atomically.
func (fs *FileStorage) saveFile(path string, content any) error {
	data, err := json.Marshal(content)
	if err != nil {
		logger.GetLogger().Error("Failed to marshal storage data", logfields.Error, err)
		return err
	}

	// Write to temp file first for atomicity
	dir := filepath.Dir(path)
	tmpFile, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		logger.GetLogger().Error("Failed to create temp file", logfields.Error, err)
		return err
	}
	tmpName := tmpFile.Name()

	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		os.Remove(tmpName)
		logger.GetLogger().Error("Failed to write temp file", logfields.Error, err)
		return err
	}

	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		os.Remove(tmpName)
		logger.GetLogger().Error("Failed to sync temp file", logfields.Error, err)
		return err
	}
	tmpFile.Close()

	// Atomic rename
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		logger.GetLogger().Error("Failed to rename temp file", logfields.Error, err, "path", path)
		return err
	}

	return nil
}

// FlushAll synchronously saves all data to disk.
// This is used during shutdown to ensure all pending writes complete.
func (fs *FileStorage) FlushAll(ctx context.Context) error {
	// FileStorage doesn't have async operations at the storage layer,
	// all writes are synchronous. The async behavior is in the stores themselves.
	// This method exists for completeness but is effectively a no-op.
	return nil
}

// Ensure FileStorage implements Storage.
var _ Storage = (*FileStorage)(nil)
