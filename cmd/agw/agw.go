package main

import (
	"context"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/cilium/tetragon/pkg/logger"

	"github.com/isovalent/hubble-fgs/pkg/fwa"
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
		cancel()
	}()

	// start CLI handler
	go cliServer(ctx)

	// Launch daemon logic
	done := make(chan error)
	go func() {
		done <- RunOnPrem(ctx, fwa.Agent, Config.DafConfig)
	}()

	// Waiting for threads to finish
	<-ctx.Done()
	logger.GetLogger().Info("AGW graceful shutdown: Exiting")
	if Config.EnableNXOS {
		nxos.Nexus.GnmiClose(ctx)
	}
	os.Exit(200)
}
