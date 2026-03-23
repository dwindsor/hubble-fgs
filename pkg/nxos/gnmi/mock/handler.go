// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package mock

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/cilium/tetragon/pkg/logger"
	gnmiproto "github.com/openconfig/gnmi/proto/gnmi"

	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi"
	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi/paths"
)

// mockHandlerRegistration holds a callback and its associated subscription paths.
type mockHandlerRegistration struct {
	handler           gnmi.SubscriptionCallback
	subscriptionPaths []string
}

// Handler implements the gnmi.GnmiHandler interface for testing without NXOS hardware.
type Handler struct {
	mu     sync.RWMutex
	data   map[string]interface{}
	closed bool

	// Subscription routing
	handlers []mockHandlerRegistration

	// Persistence
	persistPath string

	// Transaction log
	txLog *TxLog

	// Error injection for testing
	getErrors map[string]error
	setErrors map[string]error
}

// NewHandler creates a new mock gNMI handler with default state.
func NewHandler() *Handler {
	return NewHandlerBuilder().Build()
}

// TxLog returns the transaction log for this handler, or nil if not configured.
func (h *Handler) TxLog() *TxLog {
	return h.txLog
}

// Close simulates closing the gNMI connection.
func (h *Handler) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	logger.GetLogger().Debug("MockGnmiHandler: Close")

	if h.closed {
		return nil
	}

	h.closed = true
	h.txLog.Close()

	return nil
}

// RegisterHandler stores the handler and its subscription paths for later dispatch.
func (h *Handler) RegisterHandler(handler gnmi.SubscriptionCallback, subscriptionPaths ...string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.handlers = append(h.handlers, mockHandlerRegistration{handler: handler, subscriptionPaths: subscriptionPaths})
	h.txLog.Log("subscribe", strings.Join(subscriptionPaths, ","), "", "")
}

// UnregisterHandler is a no-op for the mock handler.
func (h *Handler) UnregisterHandler(handler gnmi.SubscriptionCallback) {
}

// StartSubscriptions fires initial gNMI notifications derived from h.data,
// simulating the initial sync that a real gNMI subscription delivers.
// Ordering within each domain is preserved: e.g. DPU count before per-DPU
// details, and per-DPU details before initState; VRF/VLAN names before
// affinity values.
func (h *Handler) StartSubscriptions(_ context.Context) {
	h.mu.RLock()
	data := make(map[string]interface{}, len(h.data))
	for k, v := range h.data {
		data[k] = v
	}
	h.mu.RUnlock()

	fired := make(map[string]bool)

	// routeVal sends a single notification for a normalized path+value pair.
	routeVal := func(normalizedPath string, val interface{}) {
		if fired[normalizedPath] {
			return
		}
		fired[normalizedPath] = true
		devPath := "device:/" + normalizedPath
		s, ok := val.(string)
		if !ok {
			return
		}
		if n, err := strconv.ParseUint(s, 10, 64); err == nil {
			h.Route(devPath, makeUintUpdate(n), false)
		} else {
			h.Route(devPath, makeStringUpdate(s), false)
		}
	}

	// routeOne fires a single path from data if it exists.
	routeOne := func(path string) {
		if val, ok := data[path]; ok {
			routeVal(path, val)
		}
	}

	// routePrefix fires all paths in data that have the given prefix,
	// optionally skipping paths that end with excludeSuffix.
	routePrefix := func(prefix, excludeSuffix string) {
		for path, val := range data {
			if !strings.HasPrefix(path, prefix) {
				continue
			}
			if excludeSuffix != "" && strings.HasSuffix(path, "/"+excludeSuffix) {
				continue
			}
			routeVal(path, val)
		}
	}

	// DPUs: count first, per-DPU details, initState last so WaitForInventory
	// unblocks only after all DPU data is available.
	numDpusPath := normalizePath(paths.DPUStoreNumDPUs)
	if numStr, ok := data[numDpusPath].(string); ok {
		if n, _ := strconv.ParseUint(numStr, 10, 64); n > 0 {
			routeOne(numDpusPath)
			routePrefix("System/sas-items/dpu-items/inst-items/", "")
			routeOne(normalizePath(paths.DPUStoreInitState))
		}
	}

	// VRFs: global name first, then service name (no affinity), then affinity last
	// so VRFs become active (all three flags set) and receive GID allocations.
	vrfDomBase := "System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/fwpolicy-items/ipvrf-items/dom-items/Dom-list"
	routePrefix("System/inst-items/Inst-list", "")
	routePrefix(vrfDomBase, "affinity")
	routePrefix(vrfDomBase, "")

	// VLANs: global fabEncap first, then service vlanId (no affinity), then affinity.
	vlanListBase := "System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/fwpolicy-items/bd-items/vlan-items/Vlan-list"
	routePrefix("System/bd-items/bd-items/BD-list", "")
	routePrefix(vlanListBase, "affinity")
	routePrefix(vlanListBase, "")

	// Device: serial number
	routeOne(normalizePath(paths.DeviceStoreSerialNumber))

	// Supervisor: reconstruct JSON blob from individual model/swVer leaf paths so
	// the device store's handleSupervisorTypeNotification can extract both values.
	modelPath := "System/ch-items/supslot-items/SupCSlot-list/sup-items/model"
	swVerPath := "System/ch-items/supslot-items/SupCSlot-list/sup-items/swVer"
	if model, ok := data[modelPath].(string); ok && model != "" {
		swVer, _ := data[swVerPath].(string)
		supJSON, _ := json.Marshal(map[string]interface{}{
			"SupCSlot-list": []interface{}{
				map[string]interface{}{
					"id": "1",
					"sup-items": map[string]interface{}{
						"model": model,
						"swVer": swVer,
					},
				},
			},
		})
		h.Route(paths.DeviceStoreSupervisorType, makeStringUpdate(string(supJSON)), false)
		fired[modelPath] = true
		fired[swVerPath] = true
	}

	// Service IP and in-service state
	routeOne(normalizePath(paths.DeviceStoreServiceIP))
	routeOne(normalizePath(paths.DeviceStoreInService))

	// HA: admin state, peers (stored as pre-marshaled JSON blob), source IP
	routeOne(normalizePath(paths.HAStoreEnabled))
	routeOne(normalizePath(paths.HAStorePeers))
	routeOne(normalizePath(paths.HAStoreHaIp))
}

// StopSubscriptions is a no-op for the mock handler.
func (h *Handler) StopSubscriptions() {
}

// Route dispatches a gNMI notification to all handlers subscribed to the given path.
func (h *Handler) Route(path string, update *gnmiproto.Update, isDelete bool) {
	h.mu.RLock()
	regs := make([]mockHandlerRegistration, len(h.handlers))
	copy(regs, h.handlers)
	h.mu.RUnlock()

	routeVal := ""
	if isDelete {
		routeVal = "delete"
	} else if update != nil && update.Val != nil {
		switch v := update.Val.Value.(type) {
		case *gnmiproto.TypedValue_StringVal:
			routeVal = v.StringVal
		case *gnmiproto.TypedValue_UintVal:
			routeVal = strconv.FormatUint(v.UintVal, 10)
		}
	}
	h.txLog.Log("route", path, routeVal, "")

	for _, reg := range regs {
		for _, subPath := range reg.subscriptionPaths {
			if paths.PathMatchesPrefix(path, subPath) {
				reg.handler(path, update, isDelete)
				break
			}
		}
	}
}

// GetDataByPrefix returns all entries whose normalized path equals or is prefixed by the query path.
func (h *Handler) GetDataByPrefix(path string) map[string]interface{} {
	h.mu.RLock()
	defer h.mu.RUnlock()
	normalizedPath := normalizePath(path)
	results := make(map[string]interface{})
	for key, value := range h.data {
		normalizedKey := strings.TrimPrefix(key, "/")
		if normalizedKey == normalizedPath || strings.HasPrefix(normalizedKey, normalizedPath+"/") {
			results[key] = value
		}
	}
	return results
}

// GetAllData returns a shallow copy of all stored path/value pairs.
func (h *Handler) GetAllData() map[string]interface{} {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make(map[string]interface{}, len(h.data))
	for k, v := range h.data {
		out[k] = v
	}
	return out
}

// GetData returns the value for a given path and whether the path was found.
func (h *Handler) GetData(path string) (interface{}, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	normalizedPath := normalizePath(path)
	v, ok := h.data[normalizedPath]
	return v, ok
}

// SetAndNotify stores the path/valueJSON pair and fires Route so domain stores update.
func (h *Handler) SetAndNotify(_ context.Context, path, valueJSON string) error {
	normalizedPath := normalizePath(path)
	h.mu.Lock()
	h.data[normalizedPath] = valueJSON
	h.mu.Unlock()
	h.persist()
	h.txLog.Log("set_notify", path, valueJSON, "")
	// If the value is a plain integer, send as UintVal so numeric gNMI
	// handlers (e.g. affinity) receive the correct TypedValue type.
	if n, err := strconv.ParseUint(valueJSON, 10, 64); err == nil {
		h.Route(path, makeUintUpdate(n), false)
	} else {
		h.Route(path, makeStringUpdate(valueJSON), false)
	}
	return nil
}

// DeleteAndNotify removes the path and fires Route with isDelete=true so domain stores update.
func (h *Handler) DeleteAndNotify(_ context.Context, path string) error {
	normalizedPath := normalizePath(path)
	h.mu.Lock()
	delete(h.data, normalizedPath)
	h.mu.Unlock()
	h.persist()
	h.txLog.Log("delete_notify", path, "", "")
	h.Route(path, nil, true)
	return nil
}

// Get performs a gNMI Get operation for a path string and returns string values.
// The path should include the origin prefix if needed (e.g., "device:/System/...").
func (h *Handler) Get(ctx context.Context, path string) ([]string, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	logger.GetLogger().Debug("MockGnmiHandler: Get", "path", path)

	// Check for injected errors
	if err, ok := h.getErrors[path]; ok {
		h.txLog.Log("get", path, "", err.Error())
		return nil, err
	}

	// Normalize path by removing leading slash and origin prefix
	normalizedPath := normalizePath(path)

	// Get data for this path
	data := h.getDataForPath(normalizedPath)
	if data == nil {
		h.txLog.Log("get", path, "", "")
		return nil, nil
	}

	// Convert to string representation
	var strs []string
	switch v := data.(type) {
	case string:
		strs = append(strs, v)
	case []byte:
		strs = append(strs, string(v))
	case map[string]interface{}:
		jsonBytes, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		strs = append(strs, string(jsonBytes))
	default:
		jsonBytes, err := json.Marshal(data)
		if err != nil {
			return nil, err
		}
		strs = append(strs, string(jsonBytes))
	}

	h.txLog.Log("get", path, strings.Join(strs, ","), "")
	return strs, nil
}

// Set performs a gNMI Set operation.
func (h *Handler) Set(ctx context.Context, path string, value any) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	logger.GetLogger().Debug("MockGnmiHandler: Set", "path", path)

	// Check for injected errors
	if err, ok := h.setErrors[path]; ok {
		h.txLog.Log("set", path, "", err.Error())
		return err
	}

	normalizedPath := normalizePath(path)
	h.data[normalizedPath] = value
	h.txLog.Log("set", path, fmt.Sprintf("%v", value), "")

	return nil
}

// Delete performs a gNMI Delete operation.
func (h *Handler) Delete(ctx context.Context, path string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	logger.GetLogger().Debug("MockGnmiHandler: Delete", "path", path)

	// Check for injected errors
	if err, ok := h.setErrors[path]; ok {
		h.txLog.Log("delete", path, "", err.Error())
		return err
	}

	normalizedPath := normalizePath(path)
	delete(h.data, normalizedPath)
	h.txLog.Log("delete", path, "", "")

	return nil
}

// getDataForPath retrieves data for a given path, handling wildcards and nested paths.
func (h *Handler) getDataForPath(path string) interface{} {
	// Normalize path by removing leading slash for comparison
	normalizedPath := strings.TrimPrefix(path, "/")

	// Try exact match first (with and without leading slash)
	if data, ok := h.data[path]; ok {
		return data
	}
	if data, ok := h.data[normalizedPath]; ok {
		return data
	}

	// Handle paths with wildcards or partial matches
	for key, value := range h.data {
		normalizedKey := strings.TrimPrefix(key, "/")
		if strings.HasPrefix(normalizedPath, normalizedKey) || strings.HasPrefix(normalizedKey, normalizedPath) {
			return value
		}
	}

	return nil
}

// persist writes h.data to disk if a persist path is configured.
// Caller must NOT hold h.mu.
func (h *Handler) persist() {
	if h.persistPath == "" {
		return
	}
	h.mu.RLock()
	snapshot := make(map[string]interface{}, len(h.data))
	for k, v := range h.data {
		snapshot[k] = v
	}
	h.mu.RUnlock()

	data, err := json.Marshal(snapshot)
	if err != nil {
		logger.GetLogger().Error("MockGnmiHandler: failed to marshal persist data", "error", err)
		return
	}

	dir := filepath.Dir(h.persistPath)
	tmpFile, err := os.CreateTemp(dir, ".tmp-mock-gnmi-*")
	if err != nil {
		logger.GetLogger().Error("MockGnmiHandler: failed to create temp file", "error", err)
		return
	}
	tmpName := tmpFile.Name()

	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		os.Remove(tmpName)
		logger.GetLogger().Error("MockGnmiHandler: failed to write temp file", "error", err)
		return
	}
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		os.Remove(tmpName)
		logger.GetLogger().Error("MockGnmiHandler: failed to sync temp file", "error", err)
		return
	}
	tmpFile.Close()

	if err := os.Rename(tmpName, h.persistPath); err != nil {
		os.Remove(tmpName)
		logger.GetLogger().Error("MockGnmiHandler: failed to rename temp file", "error", err)
		return
	}
	logger.GetLogger().Debug("MockGnmiHandler: persisted data", "path", h.persistPath)
}

// loadPersisted reads persisted data from disk into h.data, replacing any
// existing entries. Returns true if data was successfully loaded, false
// otherwise (file missing, unreadable, or unparseable).
// Must be called during initialization (no concurrent access).
func (h *Handler) loadPersisted() bool {
	if h.persistPath == "" {
		return false
	}
	raw, err := os.ReadFile(h.persistPath)
	if err != nil {
		if os.IsNotExist(err) {
			logger.GetLogger().Debug("MockGnmiHandler: no persist file found, starting fresh", "path", h.persistPath)
			return false
		}
		logger.GetLogger().Error("MockGnmiHandler: failed to read persist file", "error", err, "path", h.persistPath)
		return false
	}
	var loaded map[string]interface{}
	if err := json.Unmarshal(raw, &loaded); err != nil {
		logger.GetLogger().Error("MockGnmiHandler: failed to unmarshal persist file", "error", err, "path", h.persistPath)
		return false
	}
	for k, v := range loaded {
		h.data[k] = v
	}
	logger.GetLogger().Info("MockGnmiHandler: loaded persisted data", "path", h.persistPath, "count", len(loaded))
	return true
}
