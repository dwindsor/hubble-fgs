package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	gops "github.com/google/gops/agent"
	"golang.org/x/sync/errgroup"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"

	"github.com/isovalent/hubble-fgs/pkg/agw"
	"github.com/isovalent/hubble-fgs/pkg/model/server/dpu"
	"github.com/isovalent/hubble-fgs/pkg/model/switchpolicy"
	"github.com/isovalent/hubble-fgs/pkg/nxos"
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
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	runtime.GOMAXPROCS(MaxProcs)

	if err := startGopsServer(); err != nil {
		logger.GetLogger().Error("Failed to start gops server", logfields.Error, err)
	}

	// Setting up logger and context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		<-signals
		logger.GetLogger().Info("Received termination signal, canceling context and exiting...")
		cancel()
	}()

	waitGroup, ctx := errgroup.WithContext(ctx)
	dpuListener := dpu.NewDPUListener(ctx, Config.DPUServerAddress)
	agwAgent := agw.NewAgent(dpuListener, switchpolicy.NewPolicyHandler(dpuListener))
	err := agwAgent.Config(ctx, Config.DafConfig)

	if err != nil {
		logger.GetLogger().Error("Configuring FWAgent failed",
			logfields.Error, err)
		return
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
