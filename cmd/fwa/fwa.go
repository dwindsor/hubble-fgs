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
	"os"
	"os/signal"
	"runtime"
	"syscall"

	gops "github.com/google/gops/agent"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"

	"github.com/isovalent/hubble-fgs/pkg/dpu"
)

const (
	MaxProcs = 128
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

func executeFWA() error {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runtime.GOMAXPROCS(MaxProcs)

	go func() {
		<-signals
		cancel()
	}()

	if err := startGopsServer(); err != nil {
		logger.GetLogger().Error("Failed to start gops server", logfields.Error, err)
	}

	logger.GetLogger().Info("Agent starting", "config", redactedConfig())
	agent := dpu.NewDPUAgent(Config.ServerAddress)

	logger.GetLogger().Info("Configuring agent")
	if err := agent.Config(ctx, Config.DafConfig, Config.DpSocketPath, Config.EnableDataplane, Config.EnableLogger); err != nil {
		logger.GetLogger().Error("Failed to configure agent", logfields.Error, err)
		return err
	}

	logger.GetLogger().Info("Setting up agent")
	if err := agent.Setup(ctx); err != nil {
		logger.GetLogger().Error("failed to setup agent", logfields.Error, err)
		return err
	}

	logger.GetLogger().Info("Marking agent as ready")
	err := agent.Ready(ctx)
	if err != nil {
		logger.GetLogger().Error("Failed to mark agent as ready", logfields.Error, err)
		return err
	}

	// Loop connecting to AGW forever, if we lose connectivity we will
	// keep trying forever. There is nothing else for this agent to do
	// except service CLI events if it can't reach its controller.
	for {
		select {
		case <-ctx.Done():
			logger.GetLogger().Info("Agent graceful shutdown")

			// If the agent needs to clean anything do it now
			agent.Close(ctx)
			return nil
		default:
			if Config.EnableAgw {
				logger.GetLogger().Info("Connecting to controller...")
				if err := agent.Connect(ctx); err != nil {
					logger.GetLogger().Error("Failed to reach controller, continuing to run headless", logfields.Error, err)
				}
			}
		}
	}
}
