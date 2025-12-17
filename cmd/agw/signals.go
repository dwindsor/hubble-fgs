// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"
	"golang.org/x/sync/errgroup"

	"github.com/isovalent/hubble-fgs/pkg/shutdown"
)

// SignalHandler interface defines cleanup operations for graceful shutdown
type SignalHandler interface {
	// CheckUpgradeState returns true if system is in upgrade mode
	CheckUpgradeState(ctx context.Context) (bool, error)
	// Cleanup performs graceful shutdown cleanup
	Cleanup(ctx context.Context) error
	// Close performs final resource cleanup
	Close(ctx context.Context) error
	// GetExitCodeForSignal returns signal-specific exit code, or 0 to use default
	GetExitCodeForSignal(sig os.Signal, inUpgrade bool) int
}

// SetupSignalHandler sets up SIGTERM/SIGINT signal handling with upgrade awareness
func SetupSignalHandler(ctx context.Context, cancel context.CancelFunc, handler SignalHandler, waitGroup *errgroup.Group, exitCode int) {
	logger.GetLogger().Info("Setting up SIGTERM/SIGINT signal handler")

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		sig := <-sigs
		logger.GetLogger().Info(fmt.Sprintf("Received signal: %v", sig))

		// Determine the exit code to use
		finalExitCode := exitCode
		// Check if system is in upgrade mode
		upgradeInProgress := false
		if handler != nil {
			inUpgrade, err := handler.CheckUpgradeState(ctx)
			if err != nil {
				logger.GetLogger().Error("Failed to get upgrade state", logfields.Error, err)
			} else {
				upgradeInProgress = inUpgrade
			}
			signalExitCode := handler.GetExitCodeForSignal(sig, inUpgrade)
			if signalExitCode != 0 {
				finalExitCode = signalExitCode
			}

			logger.GetLogger().Info("Using signal-specific exit code", "signal", sig, "exitCode", finalExitCode)
		}

		if upgradeInProgress {
			// Skip service redirection cleanup
			logger.GetLogger().Info("Skip cleanup for upgrade_in_progress")
		} else if handler != nil {
			// Perform graceful cleanup for SIGTERM during normal operation
			if exitCode == 201 {
				if err := handler.Cleanup(ctx); err != nil {
					logger.GetLogger().Error("Cleanup failed", logfields.Error, err)
				}
			}
		}

		// Cancel all goroutines.
		// This will propagate context cancellation to all goroutines started with waitGroup.Go.
		cancel()

		// Wait for goroutines in the errGroup to complete gracefully
		if waitGroup != nil {
			if err := waitGroup.Wait(); err != nil {
				logger.GetLogger().Error("signalhandler: Error waiting for goroutines", logfields.Error, err)
			}
		}
		// Final resource cleanup
		if handler != nil {
			if err := handler.Close(ctx); err != nil {
				logger.GetLogger().Error("Final cleanup failed", logfields.Error, err)
			}
		}

		// Exit using shutdown manager instead of direct os.Exit
		shutdown.Exit(finalExitCode)
	}()
}
