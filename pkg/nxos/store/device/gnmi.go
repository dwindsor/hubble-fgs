// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package device

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/cilium/tetragon/pkg/logger"
	gnmiproto "github.com/openconfig/gnmi/proto/gnmi"

	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi"
	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi/paths"
	"github.com/isovalent/hubble-fgs/pkg/shutdown"
)

// HandleGnmiNotification processes a gNMI notification for device state.
// It matches incoming paths against the DeviceStore* subscription paths defined in the paths package.
func (s *deviceStore) HandleGnmiNotification(ctx context.Context, path string, update *gnmiproto.Update, isDelete bool) {
	// Handling all delete paths
	if isDelete {
		switch {
		case paths.PathMatches(path, paths.DeviceStoreProxyServer):
			s.SetProxyServer(ctx, "")
			logger.GetLogger().Debug("Proxy server cleared via gNMI delete notification")
		case paths.PathMatches(path, paths.DeviceStoreProxyPort):
			s.SetProxyPort(ctx, 0)
			logger.GetLogger().Debug("Proxy port cleared via gNMI delete notification")
		case paths.PathMatches(path, paths.DeviceStoreInService):
			s.SetInService(ctx, InServiceStateOutOfService)
			logger.GetLogger().Info("InService path deleted via gNMI, treated as out-of-service")
		default:
			logger.GetLogger().Warn("Failed to handle device gNMI delete notification", "path", path)
		}
		return
	}

	// Checking update value
	value := update.GetVal()

	// Handling all update paths
	switch {
	case paths.PathMatches(path, paths.DeviceStoreConnToken):
		if strVal, ok := gnmi.ExtractStringValue(value); ok && strVal != "" {
			restartNeeded, err := s.SetToken(ctx, strVal)
			if err != nil {
				logger.GetLogger().Error("Failed to set token from gNMI notification", "error", err)
			} else if restartNeeded {
				logger.GetLogger().Info("Token changed via gNMI notification, triggering graceful restart", "len", len(strVal))
				shutdown.TriggerShutdown(shutdown.RestartExitCode)
			}
		}

	case paths.PathMatches(path, paths.DeviceStoreProxyServer):
		// FIXME: Current bug where this does not match on removal
		// Needs an NX fix
		if strVal, ok := gnmi.ExtractStringValue(value); ok {
			s.SetProxyServer(ctx, strVal)
			logger.GetLogger().Debug("Proxy server updated via gNMI notification", "server", strVal)
		}

	case paths.PathMatches(path, paths.DeviceStoreProxyPort):
		if uintVal, ok := gnmi.ExtractUint32Value(value); ok {
			s.SetProxyPort(ctx, uintVal)
			logger.GetLogger().Debug("Proxy port updated via gNMI notification", "port", uintVal)
		}

	// Note: DeviceStoreAdmissionStatus and DeviceStoreConnectionStatus are AGW-OWNED paths.
	// NX-OS never writes to these paths - AGW manages them via gNMI SET operations.
	// Do NOT subscribe to or handle notifications for these paths.

	case paths.PathMatches(path, paths.DeviceStoreInService):
		if strVal, ok := gnmi.ExtractStringValue(value); ok {
			s.SetInService(ctx, strVal)
			logger.GetLogger().Debug("InService updated via gNMI notification", "operState", strVal)
		}

	case paths.PathMatches(path, paths.DeviceStoreSerialNumber):
		if strVal, ok := gnmi.ExtractStringValue(value); ok && strVal != "" {
			s.SetSerialNumber(ctx, strVal)
			logger.GetLogger().Debug("Serial number updated via gNMI notification", "serial", strVal)
		}

	case paths.PathMatches(path, paths.DeviceStoreModel):
		if strVal, ok := gnmi.ExtractStringValue(value); ok && strVal != "" {
			s.SetModel(ctx, strVal)
			logger.GetLogger().Debug("Model updated via gNMI notification", "model", strVal)
		}

	case paths.PathMatches(path, paths.DeviceStoreServiceIP):
		if strVal, ok := gnmi.ExtractStringValue(value); ok && strVal != "" {
			s.SetServiceIP(ctx, strVal)
			logger.GetLogger().Debug("Service IP updated via gNMI notification", "ip", strVal)
		}

	case paths.PathMatches(path, paths.DeviceStoreSupervisorType):
		// Grabs SoftwareVersion
		s.handleSupervisorTypeNotification(ctx, path, value)

	case paths.PathMatches(path, paths.DeviceStoreLoadBalancingMode):
		if strVal, ok := gnmi.ExtractStringValue(value); ok {
			s.SetLbMode(ctx, strVal)
			logger.GetLogger().Debug("LbMode updated via gNMI notification", "mode", strVal)
		}

	default:
		logger.GetLogger().Warn("Failed to handle device gNMI update notification", "path", path)
	}
}

// supervisorSlotJSON is the JSON structure sent by NX-OS for supslot-items notifications.
type supervisorSlotJSON struct {
	SupCSlotList []struct {
		ID       string `json:"id"`
		SupItems struct {
			Model string `json:"model"`
			SwVer string `json:"swVer"`
		} `json:"sup-items"`
	} `json:"SupCSlot-list"`
}

// handleSupervisorTypeNotification handles supervisor slot notifications.
// NX-OS may send either:
//   - A JSON blob with the full SupCSlot-list (parent-level notification), from which
//     model and software version are extracted directly.
//   - A leaf "supervisor" type string, in which case a gNMI GET is performed to fetch swVer.
func (s *deviceStore) handleSupervisorTypeNotification(ctx context.Context, path string, value *gnmiproto.TypedValue) {
	strVal, ok := gnmi.ExtractStringValue(value)
	if !ok {
		return
	}

	// Try to parse as a JSON chassis notification first.
	var slotData supervisorSlotJSON
	if err := json.Unmarshal([]byte(strVal), &slotData); err == nil {
		for _, slot := range slotData.SupCSlotList {
			if slot.SupItems.Model != "" {
				s.SetModel(ctx, slot.SupItems.Model)
				logger.GetLogger().Debug("Model updated via supervisor chassis notification", "model", slot.SupItems.Model)
			}
			if slot.SupItems.SwVer != "" {
				s.SetSoftwareVersion(ctx, slot.SupItems.SwVer)
				logger.GetLogger().Debug("Software version updated via supervisor chassis notification", "version", slot.SupItems.SwVer)
			}
		}
		return
	}

	// Fall back to leaf "supervisor" type: perform a gNMI GET for swVer.
	if strVal != "supervisor" {
		return
	}

	idx := strings.LastIndex(path, "/")
	if idx < 0 {
		return
	}
	swVerPath := path[:idx] + "/swVer"

	s.mu.RLock()
	handler := s.gnmiHandler
	s.mu.RUnlock()

	if handler == nil {
		return
	}

	strs, err := handler.Get(ctx, swVerPath)
	if err != nil {
		logger.GetLogger().Warn("Failed to GET swVer for supervisor", "path", swVerPath, "error", err)
		return
	}

	for _, str := range strs {
		if str == "" {
			continue
		}
		s.SetSoftwareVersion(ctx, str)
		logger.GetLogger().Debug("Software version updated via supervisor type gNMI GET", "version", str)
		return
	}
}
