package agw

import (
	"context"
	"os"
	"sync"

	"github.com/cilium/tetragon/pkg/logger"
	"golang.org/x/sync/errgroup"
)

// Exit codes for AGW process control
const (
	RestartExitCode   = 200 // Triggers AGW restart via init script
	TerminateExitCode = 201 // Terminates AGW without restart
)

// ShutdownManager handles centralized AGW restart with proper cleanup
type ShutdownManager struct {
	cancelFunc   context.CancelFunc
	waitGroup    *errgroup.Group
	cleanupFuncs []func(context.Context) error
	mu           sync.Mutex
}

var globalShutdownManager *ShutdownManager
var initOnce sync.Once

// RestartFunc is a function type for restart callbacks
type RestartFunc func(ctx context.Context, reason string)

// Global restart function that can be set from outside
var GlobalRestartFunc RestartFunc

// InitializeShutdown sets up the global shutdown manager
// Called once at agw startup with context and wait group
func InitializeShutdown(cancel context.CancelFunc, waitGroup *errgroup.Group) {
	initOnce.Do(func() {
		globalShutdownManager = &ShutdownManager{
			cancelFunc:   cancel,
			waitGroup:    waitGroup,
			cleanupFuncs: make([]func(context.Context) error, 0),
		}
		// Set the global restart function
		GlobalRestartFunc = RestartAGW
		logger.GetLogger().Info("Initialized centralized shutdown manager")
	})
}

// RegisterCleanup adds a cleanup function that will be called before exit
// Components can register cleanup functions (like GnmiClose, resource cleanup, etc.)
func RegisterCleanup(cleanupFunc func(context.Context) error) {
	if globalShutdownManager == nil {
		logger.GetLogger().Error("Shutdown manager not initialized - call InitializeShutdown first")
		return
	}

	globalShutdownManager.mu.Lock()
	defer globalShutdownManager.mu.Unlock()
	globalShutdownManager.cleanupFuncs = append(globalShutdownManager.cleanupFuncs, cleanupFunc)
}

// RestartAGW performs centralized graceful restart with proper cleanup sequence:
// 1. Cancel context (signals all goroutines to stop)
// 2. Wait for all goroutines to complete
// 3. Run all registered cleanup functions
// 4. Exit with RestartExitCode (triggers restart via init script)
func RestartAGW(ctx context.Context, reason string) {
	logger.GetLogger().Info("Performing AGW shutdown", "reason", reason, "exitCode", RestartExitCode)

	if globalShutdownManager == nil {
		// This should not happen if InitializeShutdown is called at startup
		logger.GetLogger().Error("Shutdown manager not initialized, falling back to direct exit")
		os.Exit(RestartExitCode)
	}

	// Step 1: Cancel context to signal all goroutines to stop
	if globalShutdownManager.cancelFunc != nil {
		logger.GetLogger().Debug("Canceling context to stop all goroutines")
		globalShutdownManager.cancelFunc()
	}

	// Step 2: Wait for all goroutines to complete
	if globalShutdownManager.waitGroup != nil {
		logger.GetLogger().Debug("Waiting for all goroutines to complete")
		if err := globalShutdownManager.waitGroup.Wait(); err != nil {
			logger.GetLogger().Error("Error waiting for goroutines", "error", err)
		}
	}

	// Step 3: Run all registered cleanup functions
	globalShutdownManager.mu.Lock()
	cleanupFuncs := make([]func(context.Context) error, len(globalShutdownManager.cleanupFuncs))
	copy(cleanupFuncs, globalShutdownManager.cleanupFuncs)
	globalShutdownManager.mu.Unlock()

	logger.GetLogger().Debug("Running cleanup functions", "count", len(cleanupFuncs))
	for i, cleanupFunc := range cleanupFuncs {
		if err := cleanupFunc(ctx); err != nil {
			logger.GetLogger().Error("Cleanup function failed", "index", i, "error", err)
		}
	}

	// Step 4: Exit with restart code is done in executeAGW()
	logger.GetLogger().Info("Agw exiting", "reason", reason, "exitCode", RestartExitCode)
}
