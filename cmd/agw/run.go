package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	enterpriseClient "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/client"
	"github.com/cilium/tetragon/pkg/watcher/conf"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/manager"

	"github.com/isovalent/hubble-fgs/pkg/commands"
	"github.com/isovalent/hubble-fgs/pkg/config"
	"github.com/isovalent/hubble-fgs/pkg/fwa"
	"github.com/isovalent/hubble-fgs/pkg/model/datapath"
	"github.com/isovalent/hubble-fgs/pkg/model/dns"
	"github.com/isovalent/hubble-fgs/pkg/model/server/dpu"
	"github.com/isovalent/hubble-fgs/pkg/netpol"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	enterpriseConf "github.com/isovalent/hubble-fgs/pkg/watcher/conf"
)

func RunOnPrem(ctx context.Context, fwaAgent *fwa.FWAgent, dpuListener *dpu.DPUListener) error {
	logger.GetLogger().Info("Agent starting...")
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Set the datapath to use DPU
	dns.SetDatapath(&datapath.DPUProgrammer{
		DpuListener: dpuListener,
	})
	s := dns.NewPolicyState()
	for _, nameGID := range Config.VrfMap {
		name := strings.Split(nameGID, ":")
		gid, _ := strconv.Atoi(name[1])
		s.AddL3Network(name[0], uint32(gid))
	}
	dns.SetRealizedState(s)

	go func() {
		err := dpuListener.Start()
		if err != nil {
			logger.GetLogger().Error("aborting DPU listener failed",
				logfields.Error, err)
			cancel()
		}
	}()

	go func() {
		// Setting up agent local state
		if Config.EnableNXOS {
			err := fwaAgent.Setup(ctx)
			if err != nil {
				logger.GetLogger().Error("Failed to setup agent",
					logfields.Error, err)
				cancel()
			}
		}
	}()

	// Setup callback to yell if DPUs are out of sync
	go fwaAgent.DpuHealthCheck(ctx)

	// Original code had an agent.Ready for now skip if its necessary we can
	// add it back.

	// Add Network Policy
	if len(Config.NetworkPolicies) > 0 {
		for _, f := range Config.NetworkPolicies {
			err := netpol.AddFromFile(f)
			if err != nil {
				return fmt.Errorf("add TetragonNetworkPolicy failed: %w", err)
			}
		}
	}

	if Config.EnableKubernetes {
		// Set up k8s client configuration in enterpriseOption.Config.
		// Ensure that Config.K8sServiceAccountAuth and enterpriseOption.Config.K8sServiceAccountAuth remain compatible.
		conf.K8sConfig = enterpriseConf.K8sConfig
		if err := setK8sServiceAccountAuth(Config.K8sServiceAccountAuth); err != nil {
			logger.GetLogger().Error("Failed to set K8sServiceAccountAuth value")
		}
		logger.GetLogger().Info("Initializing Kubernetes Manager for on-prem deployment")
		kubernetesManager := manager.Get()
		kubernetesManager.Start(ctx)

		// TODO: Wait for configmap to be ready
		err := config.AddConfigMapInformer(ctx, kubernetesManager)
		if err != nil {
			logger.GetLogger().Error("configmap failed")
			return err
		}

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

	logger.GetLogger().Info("Agent startup complete.")

	<-ctx.Done()
	return nil
}

func setK8sServiceAccountAuth(val interface{}) error {
	// If both configs expect a string, assert and assign.
	strVal, ok := val.(string)
	if !ok {
		return fmt.Errorf("K8sServiceAccountAuth must be a string, got %T", val)
	}
	enterpriseOption.Config.K8sServiceAccountAuth = strVal
	return nil
}

func cliServer(ctx context.Context, fwaAgent *fwa.FWAgent) error {
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

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	logger.GetLogger().Info("CLI server listening", "path", serverPath)

	isCtxDone := func(ctx context.Context) bool {
		select {
		case <-ctx.Done():
			return true
		default:
			return false
		}
	}

	for !isCtxDone(ctx) {
		conn, err := listener.Accept()
		switch {
		case isCtxDone(ctx):
			if conn != nil {
				conn.Close()
			}
			return nil
		case err != nil:
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

		msg, err := commands.Handler(ctx, fwaAgent, rxJson)
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

	return nil
}
