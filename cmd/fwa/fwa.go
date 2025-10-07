package main

import (
	"context"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"

	"github.com/isovalent/hubble-fgs/pkg/dpu"
)

const (
	MaxProcs = 128
)

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

	logger.GetLogger().Info("Agent starting")
	agent := dpu.NewDPUAgent(Config.ServerAddress)

	logger.GetLogger().Info("Configuring agent")
	if err := agent.Config(ctx, Config.DafConfig, Config.DpSocketPath); err != nil {
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
			logger.GetLogger().Info("Connecting to controller...")
			if err := agent.Connect(ctx); err != nil {
				logger.GetLogger().Error("Failed to reach controller, continuing to run headless", logfields.Error, err)
			}
		}
	}
}
