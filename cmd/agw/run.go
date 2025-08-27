package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"

	enterpriseClient "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/client"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/manager"

	"github.com/isovalent/hubble-fgs/pkg/commands"
	"github.com/isovalent/hubble-fgs/pkg/fwa"
	"github.com/isovalent/hubble-fgs/pkg/model/server/dpu"
	"github.com/isovalent/hubble-fgs/pkg/netpol"
)

func RunOnPrem(ctx context.Context, agent *fwa.FWAgent, configPath string) error {
	logger.GetLogger().Info("Agent starting")
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Configuring agent
	err := agent.Config(ctx, configPath)
	if err != nil {
		return err
	}

	// Setting up agent local state
	if Config.EnableNXOS {
		err = agent.Setup(ctx)
		if err != nil {
			logger.GetLogger().Error("Failed to setup agent",
				logfields.Error, err)
			return err
		}
	}

	// Setup server to listen for DPUs
	go func() {
		server := dpu.NewDPUListener(ctx, Config.DPUServerAddress)
		err := server.Start()
		if err != nil {
			logger.GetLogger().Error("aborting DPU listener failed",
				logfields.Error, err)
			cancel()
		}
	}()

	// Setup callback to yell if DPUs are out of sync
	go agent.DpuHealthCheck(ctx)

	// Original code had an agent.Ready for now skip if its necessary we can
	// add it back.

	// Add Network Policy
	if len(Config.NetworkPolicies) > 0 {
		for _, f := range Config.NetworkPolicies {
			err = netpol.AddFromFile(f)
			if err != nil {
				return fmt.Errorf("add TetragonNetworkPolicy failed: %w", err)
			}
		}
	}

	if Config.EnableKubernetes {
		kubernetesManager := manager.Get()
		kubernetesManager.Start(ctx)

		crds := make(map[string]struct{})
		crds[enterpriseClient.TetragonNetworkPolicyCRD.ResName] = struct{}{}
		if len(crds) > 0 {
			err = kubernetesManager.WaitCRDs(ctx, crds)
			if err != nil {
				return err
			}
		}
		netpol.AddTetragonNetworkPolicyInformer(ctx, kubernetesManager)
	}

	<-ctx.Done()
	return nil
}

func cliServer(ctx context.Context) error {
	serverPath := commands.CLI_SOCK

	// Clean up any old socket file before listening
	if _, err := os.Stat(serverPath); err == nil {
		if err := os.Remove(serverPath); err != nil {
			log.Fatalf("Error removing old socket: %v", err)
		}
	}

	// Create a socket for agwctl
	listener, err := net.Listen("unix", serverPath)
	if err != nil {
		return err
	}
	defer listener.Close()

	logger.GetLogger().Info("CLI server listening", "path", serverPath)
	for {
		select {
		case <-ctx.Done():
			listener.Close()
			logger.GetLogger().Info("Context cancelled, shutting down gracefully")
			return nil
		default:
			conn, err := listener.Accept()
			if err != nil {
				logger.GetLogger().Error("Failed to accept connection", logfields.Error, err)
				continue
			}

			decode := json.NewDecoder(conn)
			encode := json.NewEncoder(conn)

			var rxJson map[string]interface{}
			err = decode.Decode(&rxJson)
			if err != nil {
				logger.GetLogger().Error("Failed to decode JSON", logfields.Error, err)
				conn.Close()
				continue
			}
			logger.GetLogger().Debug("Received JSON:", "json", rxJson)

			msg, err := commands.Handler(ctx, rxJson)
			if err != nil {
				logger.GetLogger().Error("Failed to handle command", logfields.Error, err)
				conn.Close()
				continue
			}
			err = encode.Encode(msg)
			if err != nil {
				logger.GetLogger().Error("Failed to encode JSON", logfields.Error, err)
				conn.Close()
				continue
			}
			conn.Close()
		}
	}
}
