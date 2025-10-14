package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"golang.org/x/sync/errgroup"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"

	"github.com/isovalent/hubble-fgs/pkg/agw"
	"github.com/isovalent/hubble-fgs/pkg/model/server/dpu"
	"github.com/isovalent/hubble-fgs/pkg/nxos"
)

func executeAGW() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	runtime.GOMAXPROCS(MaxProcs)

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
	agwAgent := agw.NewAgent(dpuListener)
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
