package agw

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
	// MAX_CONNECTION_RETRIES is the number of failed attempts before declaring connection down
	MAX_CONNECTION_RETRIES = 3
)

// AGWAgent interface for updating NXOS connection status
type AGWAgent interface {
	SetConnectionStatus(ctx context.Context, status bool, nxosMode bool)
}

// ConnectionMonitor manages Kubernetes connection health monitoring
type ConnectionMonitor struct {
	mu               sync.RWMutex
	lastEventTime    time.Time
	connectionStatus bool
	failedAttempts   int
	agwAgent         AGWAgent
	nxosMode         bool
	manager          *manager.ControllerManager
}

// NewConnectionMonitor creates a new connection monitor
func NewConnectionMonitor(agwAgent AGWAgent, nxosMode bool, mgr *manager.ControllerManager) *ConnectionMonitor {
	return &ConnectionMonitor{
		lastEventTime:    time.Now(),
		connectionStatus: true, // Start assuming connection is up
		agwAgent:         agwAgent,
		nxosMode:         nxosMode,
		manager:          mgr,
		failedAttempts:   0, // Start with no failed attempts
	}
}

// UpdateLastEventTime updates the last event time to the current time in a thread-safe manner.
func (cm *ConnectionMonitor) UpdateLastEventTime() {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.lastEventTime = time.Now()
}

// GetLastEventTime returns the timestamp of the most recent event.
func (cm *ConnectionMonitor) GetLastEventTime() time.Time {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.lastEventTime
}

// SetConnectionStatus updates the connection status in a thread-safe manner and only calls AGWAgent if status changed
func (cm *ConnectionMonitor) SetConnectionStatus(ctx context.Context, status bool) {
	cm.mu.Lock()
	currentStatus := cm.connectionStatus
	cm.connectionStatus = status
	cm.mu.Unlock()

	// Only call AGWAgent if the status actually changed
	if currentStatus != status && cm.agwAgent != nil {
		logger.GetLogger().Info("Connection status changed", "from", currentStatus, "to", status)
		cm.agwAgent.SetConnectionStatus(ctx, status, cm.nxosMode)
	}
}

// GetConnectionStatus returns the current connection status in a thread-safe manner
func (cm *ConnectionMonitor) GetConnectionStatus() bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.connectionStatus
}

// incrementFailedAttempts increments the failed attempts counter
func (cm *ConnectionMonitor) incrementFailedAttempts() int {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.failedAttempts++
	return cm.failedAttempts
}

// resetFailedAttempts resets the failed attempts counter to zero
func (cm *ConnectionMonitor) resetFailedAttempts() {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.failedAttempts = 0
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
			// Reset failed attempts since we received an event
			cm.resetFailedAttempts()
			// Successfully received event - connection is up
			cm.SetConnectionStatus(ctx, CONNECTION_STATUS_UP)
		},
		UpdateFunc: func(_ any, _ any) {
			// Update last event time first
			cm.UpdateLastEventTime()
			// Reset failed attempts since we received an event
			cm.resetFailedAttempts()
			// Successfully received event - connection is up
			cm.SetConnectionStatus(ctx, CONNECTION_STATUS_UP)
		},
		DeleteFunc: func(_ any) {
			// Update last event time first
			cm.UpdateLastEventTime()
			// Reset failed attempts since we received an event
			cm.resetFailedAttempts()
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
				// Reset failed attempts since we have recent events
				cm.resetFailedAttempts()
				continue
			}

			// No recent add/update/delete events from informer - test k8s controller connection directly.
			logger.GetLogger().Debug("No recent ConfigMap events - testing connection directly")
			connected := cm.testK8sControllerConnection(ctx)

			if !connected {
				failedCount := cm.incrementFailedAttempts()
				logger.GetLogger().Warn("K8s controller connection failed",
					"attempts", failedCount,
					"maxRetries", MAX_CONNECTION_RETRIES)

				if failedCount >= MAX_CONNECTION_RETRIES {
					if isConnected {
						logger.GetLogger().Error("K8s controller connection lost after maximum retries - setting status to down",
							"failedAttempts", failedCount)
						isConnected = false
						cm.SetConnectionStatus(ctx, CONNECTION_STATUS_DOWN)
					}
					// Reset failed attempts to avoid unbound growth of the counter.
					cm.resetFailedAttempts()
				}
			} else {
				// Connection successful - reset failed attempts
				cm.resetFailedAttempts()
				if !isConnected {
					logger.GetLogger().Info("Kubernetes connection restored - setting status to up")
					isConnected = true
					cm.SetConnectionStatus(ctx, CONNECTION_STATUS_UP)
				}
			}
		}
	}
}

// testK8sControllerConnection tests the connection to Kubernetes API by attempting to list ConfigMaps
func (cm *ConnectionMonitor) testK8sControllerConnection(ctx context.Context) bool {
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

	return true
}
