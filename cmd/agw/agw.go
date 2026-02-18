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
	"runtime"

	gops "github.com/google/gops/agent"
	"golang.org/x/sync/errgroup"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"

	"github.com/isovalent/hubble-fgs/pkg/agw"
	hasvr "github.com/isovalent/hubble-fgs/pkg/grpc/hasvr"
	"github.com/isovalent/hubble-fgs/pkg/model/switchpolicy"
	"github.com/isovalent/hubble-fgs/pkg/nxos"
	"github.com/isovalent/hubble-fgs/pkg/shutdown"
)

const (
	haServerPort = 8883
)

func startGopsServer() error {
	if Config.GopsAddr == "" {
		return nil
	}

	if err := gops.Listen(gops.Options{
		Addr:                   Config.GopsAddr,
		ReuseSocketAddrAndPort: true,
	}); err != nil {
		return err
	}

	logger.GetLogger().Info("Starting gops server", "addr", Config.GopsAddr)

	return nil
}

func executeAGW() {
	runtime.GOMAXPROCS(MaxProcs)

	if err := startGopsServer(); err != nil {
		logger.GetLogger().Error("Failed to start gops server", logfields.Error, err)
	}

	// Setting up logger and context
	ctx, cancel := context.WithCancel(context.Background())

	waitGroup, ctx := errgroup.WithContext(ctx)

	// Setup centralized shutdown manager
	shutdown.SetupShutdownManager(ctx, cancel, waitGroup)

	// Create AGW signal handler
	agwSignalHandler := &AGWSignalHandler{
		enableNXOS: Config.EnableNXOS,
	}
	// Setup signal handling
	SetupSignalHandler(ctx, cancel, agwSignalHandler, waitGroup, shutdown.RestartExitCode)

	dpuListener := switchpolicy.NewDPUListener(ctx, Config.DPUServerAddress)
	agwAgent := agw.NewAgent(dpuListener, switchpolicy.NewPolicyHandler(ctx, dpuListener))
	err := agwAgent.Config(ctx, Config.DafConfig)

	if err != nil {
		logger.GetLogger().Error("Configuring FWAgent failed",
			logfields.Error, err)
		return
	}

	// HA is always enabled - it will only connect to peers when configured
	logger.GetLogger().Info("Starting HA service...")
	waitGroup.Go(func() error {
		err := hasvr.RunServer(ctx, haServerPort)
		if err != nil {
			return fmt.Errorf("starting HA server failed: %w", err)
		}
		return nil
	})

	waitGroup.Go(func() error {
		err := cliServer(ctx, agwAgent)
		if err != nil {
			return fmt.Errorf("starting CLI server failed: %w", err)
		}
		return nil
	})

	// Launch daemon logic
	waitGroup.Go(func() error {
		err := RunOnPrem(ctx, agwAgent, dpuListener)
		if err != nil {
			return fmt.Errorf("running on-prem failed: %w", err)
		}
		return nil
	})

	// main thread Wait for all goroutines to complete using shutdown manager
	shutdown.Wait()
}

// Simple signal handler for AGW
type AGWSignalHandler struct {
	enableNXOS bool
}

func (s *AGWSignalHandler) CheckUpgradeState(ctx context.Context) (bool, error) {
	if s.enableNXOS {
		return nxos.Nexus.CheckUpgradeState(ctx)
	}
	// AGW doesn't have upgrade state logic, always return false
	return false, nil
}

func (s *AGWSignalHandler) Cleanup(ctx context.Context) error {
	if s.enableNXOS {
		if err := nxos.Nexus.Cleanup(ctx); err != nil {
			return err
		}
	}
	// AGW-specific cleanup logic can be added here
	logger.GetLogger().Debug("AGW cleanup completed")
	return nil
}

func (s *AGWSignalHandler) Close(ctx context.Context) error {
	// Close NXOS connection if enabled
	if s.enableNXOS {
		return nxos.Nexus.Close(ctx)
	}
	logger.GetLogger().Debug("AGW close completed")
	return nil
}

func (s *AGWSignalHandler) GetExitCodeForSignal(sig os.Signal, inUpgrade bool) int {
	if s.enableNXOS {
		return nxos.Nexus.GetExitCodeForSignal(sig, inUpgrade)
	}
	// AGW prefers RestartExitCode for normal shutdown (agw restart)
	return shutdown.RestartExitCode
}
