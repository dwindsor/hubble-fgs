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
	"github.com/isovalent/hubble-fgs/pkg/model/server/dpu"
	"github.com/isovalent/hubble-fgs/pkg/model/switchpolicy"
	"github.com/isovalent/hubble-fgs/pkg/nxos"
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
	defer cancel()

	waitGroup, ctx := errgroup.WithContext(ctx)
	// Create AGW signal handler
	agwSignalHandler := &AGWSignalHandler{
		enableNXOS: Config.EnableNXOS,
	}
	// Setup signal handling
	SetupSignalHandler(ctx, cancel, agwSignalHandler, waitGroup, 200)

	dpuListener := dpu.NewDPUListener(ctx, Config.DPUServerAddress)
	agwAgent := agw.NewAgent(dpuListener, switchpolicy.NewPolicyHandler(ctx, dpuListener))
	err := agwAgent.Config(ctx, Config.DafConfig)

	if err != nil {
		logger.GetLogger().Error("Configuring FWAgent failed",
			logfields.Error, err)
		return
	}

	if Config.Ha {
		logger.GetLogger().Info("Starting HA service...")
		waitGroup.Go(func() error {
			err := hasvr.RunServer(ctx, haServerPort)
			if err != nil {
				return fmt.Errorf("starting HA server failed: %w", err)
			}
			return nil
		})
	}

	waitGroup.Go(func() error {
		err := cliServer(ctx, agwAgent)
		if err != nil {
			return fmt.Errorf("starting CLI server failed: %w", err)
		}
		return nil
	})

	// Launch daemon logic
	waitGroup.Go(func() error {
		err := RunOnPrem(ctx, cancel, agwAgent, dpuListener)
		if err != nil {
			return fmt.Errorf("running on-prem failed: %w", err)
		}
		return nil
	})

	if err := waitGroup.Wait(); err != nil {
		logger.GetLogger().Error("AGW failed", logfields.Error, err)
	} else {
		logger.GetLogger().Info("AGW graceful shutdown: Exiting")
	}
	if Config.EnableNXOS {
		nxos.Nexus.GnmiClose(ctx)
	}
	os.Exit(200)
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
	// AGW prefers exit code 200 for normal shutdown (agw restart)
	return 200
}
