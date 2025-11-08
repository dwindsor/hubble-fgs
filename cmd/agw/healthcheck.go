package main

import (
	"context"
	"sync"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/manager"
)

const (
	// CONNECTION_TIMEOUT is the duration of inactivity (no events received), before testing the connection directly.
	CONNECTION_TIMEOUT = 1 * time.Minute
	// CONNECTION_STATUS_UP represents a connected state
	CONNECTION_STATUS_UP = true
	// CONNECTION_STATUS_DOWN represents a disconnected state
	CONNECTION_STATUS_DOWN = false
)

// AGWAgent interface for updating NXOS connection status
type AGWAgent interface {
	SetConnectionStatus(ctx context.Context, status bool, nxosMode bool)
}

// ConnectionMonitor manages Kubernetes connection health monitoring
type ConnectionMonitor struct {
	lastEventTime      time.Time
	lastEventMu        sync.RWMutex
	connectionStatus   bool
	connectionStatusMu sync.RWMutex
	agwAgent           AGWAgent
	nxosMode           bool
	manager            *manager.ControllerManager
}

// NewConnectionMonitor creates a new connection monitor
func NewConnectionMonitor(agwAgent AGWAgent, nxosMode bool, mgr *manager.ControllerManager) *ConnectionMonitor {
	return &ConnectionMonitor{
		lastEventTime:    time.Now(),
		connectionStatus: true, // Start assuming connection is up
		agwAgent:         agwAgent,
		nxosMode:         nxosMode,
		manager:          mgr,
	}
}

// UpdateLastEventTime updates the last event time to the current time in a thread-safe manner.
func (cm *ConnectionMonitor) UpdateLastEventTime() {
	cm.lastEventMu.Lock()
	defer cm.lastEventMu.Unlock()
	cm.lastEventTime = time.Now()
}

// GetLastEventTime returns the timestamp of the most recent event.
func (cm *ConnectionMonitor) GetLastEventTime() time.Time {
	cm.lastEventMu.RLock()
	defer cm.lastEventMu.RUnlock()
	return cm.lastEventTime
}

// SetConnectionStatus updates the connection status in a thread-safe manner and only calls AGWAgent if status changed
func (cm *ConnectionMonitor) SetConnectionStatus(ctx context.Context, status bool) {
	cm.connectionStatusMu.Lock()
	currentStatus := cm.connectionStatus
	cm.connectionStatus = status
	cm.connectionStatusMu.Unlock()

	// Only call AGWAgent if the status actually changed
	if currentStatus != status && cm.agwAgent != nil {
		logger.GetLogger().Info("Connection status changed", "from", currentStatus, "to", status)
		cm.agwAgent.SetConnectionStatus(ctx, status, cm.nxosMode)
	}
}

// GetConnectionStatus returns the current connection status in a thread-safe manner
func (cm *ConnectionMonitor) GetConnectionStatus() bool {
	cm.connectionStatusMu.RLock()
	defer cm.connectionStatusMu.RUnlock()
	return cm.connectionStatus
}

// StartMonitoring starts the connection monitoring goroutine
func (cm *ConnectionMonitor) StartMonitoring(ctx context.Context) {
	go cm.monitorConnection(ctx)
}

// CreateEventHandlers returns event handlers that update connection status
func (cm *ConnectionMonitor) CreateEventHandlers(ctx context.Context) cache.ResourceEventHandlerFuncs {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(_ any) {
			// Update last event time first
			cm.UpdateLastEventTime()
			// Successfully received event - connection is up
			cm.SetConnectionStatus(ctx, CONNECTION_STATUS_UP)
		},
		UpdateFunc: func(_ any, _ any) {
			// Update last event time first
			cm.UpdateLastEventTime()
			// Successfully received event - connection is up
			cm.SetConnectionStatus(ctx, CONNECTION_STATUS_UP)
		},
		DeleteFunc: func(_ any) {
			// Update last event time first
			cm.UpdateLastEventTime()
			// Successfully received event - connection is up
			cm.SetConnectionStatus(ctx, CONNECTION_STATUS_UP)
		},
	}
}

// hasRecentEvent returns true if the last event time is within the CONNECTION_TIMEOUT window.
func (cm *ConnectionMonitor) hasRecentEvent() bool {
	// Calculate the duration that has passed since that last event time,
	// and compare it to the CONNECTION_TIMEOUT.
	return time.Since(cm.GetLastEventTime()) < CONNECTION_TIMEOUT
}

// monitorConnection monitors for connection issues by checking if events are still being received
func (cm *ConnectionMonitor) monitorConnection(ctx context.Context) {
	ticker := time.NewTicker(CONNECTION_TIMEOUT)
	defer ticker.Stop()

	// Assume connection is initially up
	isConnected := true

	for {
		select {
		case <-ctx.Done():
			logger.GetLogger().Info("connection monitor stopping")
			return
		case <-ticker.C:
			// Test connection by attempting to list ConfigMaps
			// First check if we've received recent events
			lastEventAge := time.Since(cm.GetLastEventTime())
			logger.GetLogger().Debug("Connection monitor check",
				"lastEventAge", lastEventAge,
				"connectionTimeout", CONNECTION_TIMEOUT,
				"isConnected", isConnected)

			if cm.hasRecentEvent() {
				// Recent event received - connection is up
				logger.GetLogger().Debug("Recent ConfigMap event detected - connection assumed good")
				if !isConnected {
					isConnected = true
					logger.GetLogger().Info("Setting connection status to success due to restored connection")
					cm.SetConnectionStatus(ctx, CONNECTION_STATUS_UP)
				}
				continue
			}

			// No recent add/update/delete events from informer - test connection directly
			logger.GetLogger().Debug("No recent ConfigMap events - testing connection directly")
			connected := cm.testKubernetesConnection(ctx)

			if !connected {
				if isConnected {
					logger.GetLogger().Error("Kubernetes connection lost - setting status to down")
					isConnected = false
					cm.SetConnectionStatus(ctx, CONNECTION_STATUS_DOWN)
				}
				logger.GetLogger().Error("Connection test failed")
			} else {
				if !isConnected {
					logger.GetLogger().Info("Kubernetes connection restored - setting status to up")
					isConnected = true
					cm.SetConnectionStatus(ctx, CONNECTION_STATUS_UP)
				}
			}
		}
	}
}

// testKubernetesConnection tests the connection to Kubernetes API by attempting to list ConfigMaps
func (cm *ConnectionMonitor) testKubernetesConnection(ctx context.Context) bool {
	logger.GetLogger().Info("testing Kubernetes connection by listing ConfigMaps")
	if cm.manager == nil || cm.manager.Manager == nil {
		logger.GetLogger().Error("ControllerManager is nil - cannot test Kubernetes connection")
		return false
	}

	// Create a timeout context for the API call
	testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Get the REST config to create a direct client (bypasses cache)
	restConfig := cm.manager.Manager.GetConfig()
	if restConfig == nil {
		logger.GetLogger().Error("Manager.GetConfig() returned nil - cannot test Kubernetes connection")
		return false
	}

	// Create a direct client that bypasses the cache
	directClient, err := client.New(restConfig, client.Options{})
	if err != nil {
		logger.GetLogger().Error("failed to create direct Kubernetes client", "error", err)
		return false
	}

	// Attempt to list ConfigMaps to test connectivity (this will hit the API server directly)
	var configMapList v1.ConfigMapList
	err = directClient.List(testCtx, &configMapList, &client.ListOptions{Limit: 1})

	if err != nil {
		logger.GetLogger().Error("failed to list ConfigMaps - connection test failed", "error", err)
		return false
	}

	// Additional check: verify the context wasn't cancelled due to timeout
	if testCtx.Err() != nil {
		logger.GetLogger().Error("K8s API call timed out - connection test failed", "error", testCtx.Err())
		return false
	}

	logger.GetLogger().Debug("K8s connection test successful")
	return true
}
