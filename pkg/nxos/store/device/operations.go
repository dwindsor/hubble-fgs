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
	"fmt"
	"os"

	"google.golang.org/protobuf/proto"

	"github.com/cilium/tetragon/pkg/logger"

	"github.com/isovalent/hubble-fgs/pkg/config/library"
	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi/paths"
	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
)

// regFailK8sAuth is the registration failure reason for invalid K8s auth tokens.
// This matches nxos.RegFailK8sAuth and is kept local to avoid circular imports.
const regFailK8sAuth = "invalid k8s service account token"

func (s *deviceStore) SetToken(ctx context.Context, newToken string) (bool, error) {
	s.mu.RLock()
	prev := s.token
	provider := s.tokenProvider
	s.mu.RUnlock()

	// If unchanged, return early
	if prev == newToken {
		logger.GetLogger().Debug("K8s auth token is unchanged")
		return false, nil
	}

	if provider != nil && !s.IsHeadlessMode() {
		// Validate the token
		if err := provider.ValidK8sAuth(newToken); err != nil {
			return false, err
		}
		// Persist via agent token
		if err := provider.SetAndPersistK8sAuthToken(newToken); err != nil {
			return false, err
		}
		// Set environment variable
		if err := os.Setenv("HYPERSHIELD_TOKEN", newToken); err != nil {
			return false, fmt.Errorf("fail to set K8s token to env: %w", err)
		}
		// Extract and set controller endpoint/port
		endpoint, port, err := provider.K8sControllerEndpoint()
		if err != nil {
			logger.GetLogger().Warn("Failed to get controller endpoint from token", "error", err)
		} else {
			s.SetControllerEndpoint(ctx, endpoint)
			s.SetControllerPort(ctx, port)
		}
	}

	s.mu.Lock()
	s.token = newToken
	// Auto-clear SkipReg when a new token arrives after a K8s auth failure.
	// This signals callers (via reload) that they should retry registration.
	if newToken != "" && s.skipReg && s.skipRegReason == regFailK8sAuth {
		s.skipReg = false
		s.skipRegReason = ""
		s.reload = true
		logger.GetLogger().Info("K8s auth token updated, clearing SkipReg and signaling reload")
	}
	s.mu.Unlock()

	s.notify(Event{Type: EventTokenChanged})
	s.persist(ctx)

	// restartNeeded is true only if there was a previous non-empty token
	restartNeeded := prev != ""
	return restartNeeded, nil
}

func (s *deviceStore) SetProxyServer(ctx context.Context, server string) {
	s.mu.Lock()
	s.proxyServer = server
	s.mu.Unlock()
	s.persist(ctx)
	s.updateProxyEnvVars()
}

func (s *deviceStore) SetProxyPort(ctx context.Context, port uint32) {
	s.mu.Lock()
	s.proxyPort = port
	s.mu.Unlock()
	s.persist(ctx)
	s.updateProxyEnvVars()
}

// updateProxyEnvVars sets http_proxy, HTTP_PROXY, https_proxy, and HTTPS_PROXY
// environment variables based on the current proxy server and port configuration.
func (s *deviceStore) updateProxyEnvVars() {
	s.mu.RLock()
	server := s.proxyServer
	port := s.proxyPort
	s.mu.RUnlock()

	var proxyURL string
	if server != "" {
		proxyURL = "http://" + server
		if port != 0 {
			proxyURL += fmt.Sprintf(":%d", port)
		}
	}

	for _, envVar := range []string{"http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY"} {
		if err := os.Setenv(envVar, proxyURL); err != nil {
			logger.GetLogger().Warn("Failed to set proxy env var", "var", envVar, "error", err)
		}
	}
}

func (s *deviceStore) SetConnectionStatus(ctx context.Context, status string, reason string) {
	s.mu.Lock()
	connChanged := s.controllerConnectionStatus != status
	s.controllerConnectionStatus = status
	s.controllerRejectReason = reason

	// Update ConnPending bit in systemState atomically.
	// In headless mode, ConnPending is never set.
	oldState := s.systemState
	if !s.headlessMode {
		if status == ControllerStateSuccess {
			s.systemState &^= sysStConnPending
		} else {
			s.systemState |= sysStConnPending
		}
	}
	stateChanged := s.systemState != oldState
	newState := s.systemState
	handler := s.gnmiHandler
	s.mu.Unlock()

	if connChanged {
		s.notify(Event{Type: EventConnectionChanged, Status: status, Reason: reason})

		// Sync connection status to NXOS via gNMI
		if handler != nil {
			if err := handler.Set(ctx, paths.DeviceStoreConnectionStatus, status); err != nil {
				logger.GetLogger().Warn("Failed to sync connection status to gNMI", "status", status, "error", err)
			}
			if reason != "" {
				if err := handler.Set(ctx, paths.DeviceStoreRejectReason, reason); err != nil {
					logger.GetLogger().Warn("Failed to sync reject reason to gNMI", "reason", reason, "error", err)
				}
			}
		}
	}

	if stateChanged && handler != nil {
		hexState := fmt.Sprintf("0x%X", newState)
		if err := handler.Set(ctx, paths.DeviceStoreSystemState, hexState); err != nil {
			logger.GetLogger().Warn("Failed to sync system state to gNMI", "state", hexState, "error", err)
		}
	}

	s.persist(ctx)
}

func (s *deviceStore) SetAdmissionStatus(ctx context.Context, status string, reason string) {
	s.mu.Lock()
	changed := s.controllerAdmissionStatus != status
	s.controllerAdmissionStatus = status
	s.controllerRejectReason = reason
	handler := s.gnmiHandler
	s.mu.Unlock()

	if changed {
		s.notify(Event{Type: EventAdmissionChanged, Reason: reason})
		s.persist(ctx)

		// Sync state to NXOS via gNMI
		if handler != nil {
			if err := handler.Set(ctx, paths.DeviceStoreAdmissionStatus, status); err != nil {
				logger.GetLogger().Warn("Failed to sync admission status to gNMI", "status", status, "error", err)
			}
		}
	}
}

func (s *deviceStore) SetSerialNumber(ctx context.Context, serial string) {
	s.mu.Lock()
	s.serialNumber = serial
	s.mu.Unlock()
	s.persist(ctx)

	// Propagate SerialNumber to config library so DPUs receive it.
	if serial != "" {
		err := library.GetRepository().UpdateConfig(v1alpha.ConfigType_CONFIG_TYPE_DPU, func(existing *v1alpha.ConfigObject) (*v1alpha.ConfigObject, error) {
			var dpuConfig *v1alpha.DpuConfig
			if existing != nil && existing.GetConfigDpu() != nil {
				dpuConfig = proto.Clone(existing.GetConfigDpu()).(*v1alpha.DpuConfig)
			} else {
				dpuConfig = &v1alpha.DpuConfig{}
			}
			dpuConfig.SerialNumber = serial
			return &v1alpha.ConfigObject{
				Type:   v1alpha.ConfigType_CONFIG_TYPE_DPU,
				Source: v1alpha.ConfigSource_CONFIG_SOURCE_LOCAL,
				Config: &v1alpha.ConfigObject_ConfigDpu{ConfigDpu: dpuConfig},
			}, nil
		})
		if err != nil {
			logger.GetLogger().Warn("Failed to update serial number in config library", "error", err)
		}
	}
}

func (s *deviceStore) SetModel(ctx context.Context, model string) {
	s.mu.Lock()
	s.model = model
	s.mu.Unlock()
	s.persist(ctx)
}

func (s *deviceStore) SetSoftwareVersion(ctx context.Context, version string) {
	s.mu.Lock()
	s.softwareVersion = version
	s.mu.Unlock()
	s.persist(ctx)
}

func (s *deviceStore) SetServiceIP(ctx context.Context, ip string) {
	s.mu.Lock()
	s.serviceIP = ip
	s.mu.Unlock()
	s.persist(ctx)

	// Propagate ServiceIP to config library so DPUs receive it.
	if ip != "" {
		err := library.GetRepository().UpdateConfig(v1alpha.ConfigType_CONFIG_TYPE_DPU, func(existing *v1alpha.ConfigObject) (*v1alpha.ConfigObject, error) {
			var dpuConfig *v1alpha.DpuConfig
			if existing != nil && existing.GetConfigDpu() != nil {
				dpuConfig = proto.Clone(existing.GetConfigDpu()).(*v1alpha.DpuConfig)
			} else {
				dpuConfig = &v1alpha.DpuConfig{}
			}
			dpuConfig.ServiceIp = ip
			return &v1alpha.ConfigObject{
				Type:   v1alpha.ConfigType_CONFIG_TYPE_DPU,
				Source: v1alpha.ConfigSource_CONFIG_SOURCE_LOCAL,
				Config: &v1alpha.ConfigObject_ConfigDpu{ConfigDpu: dpuConfig},
			}, nil
		})
		if err != nil {
			logger.GetLogger().Warn("Failed to update service IP in config library", "error", err)
		}
	}
}

func (s *deviceStore) SetHeadlessMode(ctx context.Context, headless bool) {
	s.mu.Lock()
	s.headlessMode = headless
	s.mu.Unlock()
	s.persist(ctx)
}

func (s *deviceStore) SetInService(ctx context.Context, inService string) {
	// Snapshot the current state and hooks under the lock so we can run hooks
	// outside the lock (avoiding deadlock if hooks call back into the store).
	// NOTE: this does not fully serialize concurrent callers — if two goroutines
	// race with different values, both may pass the early-return check. In
	// practice SetInService is called from the single gNMI dispatch goroutine.
	s.mu.Lock()
	if s.inService == inService {
		s.mu.Unlock()
		return
	}
	old := s.inService
	preHook := s.preInServiceHook
	postHook := s.postInServiceHook
	s.mu.Unlock()

	// Pre-hook: runs BEFORE state changes (for in-service redirect programming).
	if preHook != nil {
		preHook(ctx, inService)
	}

	s.mu.Lock()
	s.inService = inService
	s.mu.Unlock()

	s.notify(Event{Type: EventInServiceChanged, Status: inService})

	// Post-hook: runs AFTER state changes and notification (for out-of-service cleanup).
	if postHook != nil {
		postHook(ctx, old, inService)
	}

	s.persist(ctx)
}

// SetPreInServiceHook registers a hook called BEFORE in-service state changes.
func (s *deviceStore) SetPreInServiceHook(hook func(ctx context.Context, newState string)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.preInServiceHook = hook
}

// SetPostInServiceHook registers a hook called AFTER in-service state changes.
func (s *deviceStore) SetPostInServiceHook(hook func(ctx context.Context, oldState, newState string)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.postInServiceHook = hook
}

func (s *deviceStore) SetSkipReg(ctx context.Context, skip bool, reason string) {
	s.mu.Lock()
	s.skipReg = skip
	s.skipRegReason = reason
	s.mu.Unlock()
	s.persist(ctx)
}

func (s *deviceStore) SetLbMode(ctx context.Context, mode string) {
	s.mu.Lock()
	changed := s.lbMode != mode
	s.lbMode = mode
	s.mu.Unlock()
	if changed {
		s.notify(Event{Type: EventLbModeChanged, Status: mode})
	}
	s.persist(ctx)
}

func (s *deviceStore) ResetRegistration(ctx context.Context) {
	s.mu.Lock()
	s.controllerAdmissionStatus = ControllerStateUnknown
	s.controllerRejectReason = ""
	s.mu.Unlock()
	s.persist(ctx)
}

func (s *deviceStore) ResetConnection(ctx context.Context) {
	s.SetConnectionStatus(ctx, ControllerStateUnknown, "")
}

func (s *deviceStore) SetControllerEndpoint(ctx context.Context, endpoint string) {
	s.mu.Lock()
	changed := s.controllerEndpoint != endpoint
	s.controllerEndpoint = endpoint
	handler := s.gnmiHandler
	s.mu.Unlock()
	s.persist(ctx)

	if handler != nil && changed {
		if err := handler.Set(ctx, paths.DeviceStoreControllerEndpoint, endpoint); err != nil {
			logger.GetLogger().Warn("Failed to sync controller endpoint to gNMI", "endpoint", endpoint, "error", err)
		}
	}
}

func (s *deviceStore) SetControllerPort(ctx context.Context, port uint32) {
	s.mu.Lock()
	changed := s.controllerPort != port
	s.controllerPort = port
	handler := s.gnmiHandler
	s.mu.Unlock()
	s.persist(ctx)

	if handler != nil && changed {
		if err := handler.Set(ctx, paths.DeviceStoreControllerPort, port); err != nil {
			logger.GetLogger().Warn("Failed to sync controller port to gNMI", "port", port, "error", err)
		}
	}
}

func (s *deviceStore) SetControllerVersion(ctx context.Context, version string) {
	s.mu.Lock()
	changed := s.controllerVersion != version
	s.controllerVersion = version
	handler := s.gnmiHandler
	s.mu.Unlock()
	s.persist(ctx)

	if handler != nil && changed {
		if err := handler.Set(ctx, paths.DeviceStoreControllerVersion, version); err != nil {
			logger.GetLogger().Warn("Failed to sync agent version to gNMI", "version", version, "error", err)
		}
	}
}

func (s *deviceStore) SetSystemState(ctx context.Context, systemState int) {
	s.mu.Lock()
	changed := s.systemState != systemState
	s.systemState = systemState
	handler := s.gnmiHandler
	s.mu.Unlock()
	s.persist(ctx)

	if handler != nil && changed {
		hexState := fmt.Sprintf("0x%X", systemState)
		if err := handler.Set(ctx, paths.DeviceStoreSystemState, hexState); err != nil {
			logger.GetLogger().Warn("Failed to sync system state to gNMI", "state", hexState, "error", err)
		}
	}
}

// UpdateSystemState atomically updates the non-ConnPending bits of systemState
// while preserving the ConnPending bit (which is owned by SetConnectionStatus).
func (s *deviceStore) UpdateSystemState(ctx context.Context, bits int) {
	s.mu.Lock()
	old := s.systemState
	s.systemState = bits | (old & sysStConnPending)
	changed := s.systemState != old
	handler := s.gnmiHandler
	newState := s.systemState
	s.mu.Unlock()
	s.persist(ctx)

	if handler != nil && changed {
		hexState := fmt.Sprintf("0x%X", newState)
		if err := handler.Set(ctx, paths.DeviceStoreSystemState, hexState); err != nil {
			logger.GetLogger().Warn("Failed to sync system state to gNMI", "state", hexState, "error", err)
		}
	}
}

func (s *deviceStore) DeleteSystemState(ctx context.Context) error {
	s.mu.RLock()
	handler := s.gnmiHandler
	s.mu.RUnlock()

	if handler == nil {
		return nil
	}

	if err := handler.Delete(ctx, paths.DeviceStoreSystemState); err != nil {
		logger.GetLogger().Warn("Failed to delete system state via gNMI", "error", err)
		return fmt.Errorf("delete system state: %w", err)
	}
	return nil
}
