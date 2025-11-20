package shutdown

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"
	"golang.org/x/sync/errgroup"
)

// Valid exit codes for AGW process control
const (
	RestartExitCode   = 200 // Triggers AGW restart via init script
	TerminateExitCode = 201 // Terminates AGW without restart
	ErrorExitCode     = 255 // Indicates an error condition
)

// ShutdownManager handles centralized process shutdown with proper cleanup
type ShutdownManager struct {
	shutdown     chan int
	errGroup     *errgroup.Group
	ctx          context.Context
	cancelFunc   context.CancelFunc
	cleanupFuncs []func(context.Context) error
	mu           sync.Mutex
	once         sync.Once
}

// NewShutdownManager creates a new shutdown manager
func NewShutdownManager(ctx context.Context, cancel context.CancelFunc, errGroup *errgroup.Group) *ShutdownManager {
	return &ShutdownManager{
		shutdown:     make(chan int, 1),
		errGroup:     errGroup,
		ctx:          ctx,
		cancelFunc:   cancel,
		cleanupFuncs: make([]func(context.Context) error, 0),
	}
}

// Register adds a cleanup function that will be called before exit
func (sm *ShutdownManager) Register(cleanupFunc func(context.Context) error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.cleanupFuncs = append(sm.cleanupFuncs, cleanupFunc)
	logger.GetLogger().Debug("Registered cleanup function", "total", len(sm.cleanupFuncs))
}

// Wait waits for shutdown signal or errgroup completion.
// If any goroutine in errgroup returns error, context is canceled.
// If shutdown channel receives signal, context is manually cancelled and all threads waited on.
func (sm *ShutdownManager) Wait() {
	sm.once.Do(func() {
		go func() {
			// Wait for errgroup completion
			err := sm.errGroup.Wait()
			// Default to restart on normal completion
			exitCode := RestartExitCode
			if err != nil {
				// Use error exit code for actual errors
				exitCode = ErrorExitCode
			}
			select {
			case sm.shutdown <- exitCode:
				// Successfully sent exit code to shutdown channel
			default:
				// Shutdown channel already has a value, ignore
			}
		}()
	})

	// Wait for either errgroup completion or manual shutdown
	exitCode := <-sm.shutdown

	logger.GetLogger().Info("Shutdown received", "exitCode", exitCode)
	sm.Shutdown(exitCode)
}

// Shutdown initiates graceful shutdown and exits with specified code
func (sm *ShutdownManager) Shutdown(exitCode int) {
	logger.GetLogger().Info("Initiating graceful shutdown", "exitCode", exitCode)

	// Step 1: Cancel context to signal all goroutines to stop
	if sm.cancelFunc != nil {
		sm.cancelFunc()
		logger.GetLogger().Debug("Context canceled, proceeding to wait for goroutines")
	}

	// Step 2: Wait for all goroutines to complete (if not already done)
	if sm.errGroup != nil {
		logger.GetLogger().Debug("Waiting for all goroutines to complete")

		// Use a timeout to prevent indefinite hanging
		done := make(chan error, 1)
		go func() {
			done <- sm.errGroup.Wait()
		}()

		select {
		case err := <-done:
			if err != nil {
				logger.GetLogger().Error("AGW failed", logfields.Error, err)
			} else {
				logger.GetLogger().Info("AGW graceful shutdown: Exiting")
			}
		case <-time.After(30 * time.Second):
			logger.GetLogger().Error("Timeout waiting for goroutines to complete, forcing shutdown")
		}
		logger.GetLogger().Debug("ErrGroup wait completed")
	}

	// Step 3: Run cleanup functions
	sm.runCleanup()
	logger.GetLogger().Debug("Cleanup functions completed")

	// Step 4: Exit with specified code
	logger.GetLogger().Debug("About to exit process", "exitCode", exitCode)
	sm.Exit(exitCode)
}

// runCleanup executes all registered cleanup functions
func (sm *ShutdownManager) runCleanup() {
	sm.mu.Lock()
	cleanupFuncs := make([]func(context.Context) error, len(sm.cleanupFuncs))
	copy(cleanupFuncs, sm.cleanupFuncs)
	sm.mu.Unlock()

	logger.GetLogger().Debug("Running cleanup functions", "count", len(cleanupFuncs))
	for i, cleanupFunc := range cleanupFuncs {
		if err := cleanupFunc(sm.ctx); err != nil {
			logger.GetLogger().Error("Cleanup function failed", "index", i, "error", err)
		}
	}
}

// Exit exits process with specified code
// This is the ONLY function that should call os.Exit() in the entire application
func (sm *ShutdownManager) Exit(code int) {
	logger.GetLogger().Info("Process exiting", "exitCode", code)
	os.Exit(code)
}

// TriggerShutdown sends a shutdown signal with a specific exit code
// This allows external components to trigger graceful shutdown with a specific exit code
func (sm *ShutdownManager) TriggerShutdown(exitCode int) {
	logger.GetLogger().Info("Shutdown triggered externally", "exitCode", exitCode)

	select {
	case sm.shutdown <- exitCode:
		// Successfully triggered shutdown with specific exit code
	default:
		// Shutdown already in progress
		logger.GetLogger().Debug("Shutdown already in progress")
	}
}

// Global shutdown manager instance
var globalShutdownManager *ShutdownManager
var globalOnce sync.Once

// SetupShutdownManager sets up the global shutdown manager
func SetupShutdownManager(ctx context.Context, cancel context.CancelFunc, errGroup *errgroup.Group) {
	globalOnce.Do(func() {
		globalShutdownManager = NewShutdownManager(ctx, cancel, errGroup)
		logger.GetLogger().Info("Setup global shutdown manager")
	})
}

// RegisterCleanup adds a cleanup function to the global shutdown manager
func RegisterCleanup(cleanupFunc func(context.Context) error) {
	if globalShutdownManager == nil {
		logger.GetLogger().Error("Global shutdown manager not setup - call SetupShutdownManager first")
		return
	}
	globalShutdownManager.Register(cleanupFunc)
}

// Wait waits for shutdown using the global shutdown manager
func Wait() {
	if globalShutdownManager == nil {
		logger.GetLogger().Error("Global shutdown manager not setup")
		os.Exit(TerminateExitCode)
	}
	globalShutdownManager.Wait()
}

// TriggerShutdown triggers external shutdown with specific exit code using the global shutdown manager
func TriggerShutdown(exitCode int) {
	if globalShutdownManager == nil {
		logger.GetLogger().Error("Global shutdown manager not setup")
		return
	}
	globalShutdownManager.TriggerShutdown(exitCode)
}

// Exit validates and exits with the given code using the global shutdown manager
func Exit(code int) {
	if globalShutdownManager == nil {
		logger.GetLogger().Error("Global shutdown manager not setup, using direct exit")
		os.Exit(code)
	}
	globalShutdownManager.Exit(code)
}
