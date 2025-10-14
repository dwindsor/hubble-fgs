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
	"golang.org/x/sync/errgroup"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/manager"

	"github.com/isovalent/hubble-fgs/pkg/agw"
	"github.com/isovalent/hubble-fgs/pkg/commands/agwctl"
	"github.com/isovalent/hubble-fgs/pkg/config"
	"github.com/isovalent/hubble-fgs/pkg/model/datapath"
	"github.com/isovalent/hubble-fgs/pkg/model/dns"
	"github.com/isovalent/hubble-fgs/pkg/model/server/dpu"
	"github.com/isovalent/hubble-fgs/pkg/netpol"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	enterpriseConf "github.com/isovalent/hubble-fgs/pkg/watcher/conf"
)

func RunOnPrem(ctx context.Context, cancel context.CancelFunc, agwAgent *agw.AgentGateway, dpuListener *dpu.DPUListener) error {
	logger.GetLogger().Info("Agent starting...")
	waitGroup, ctx := errgroup.WithContext(ctx)

	// Set the datapath to use DPU
	dns.SetDatapath(&datapath.DPUProgrammer{
		DpuListener: dpuListener,
	})
	s := dns.GetRealizedState()
	vrfMap := make(map[string]uint32)
	for _, nameGID := range Config.VrfMap {
		name := strings.Split(nameGID, ":")
		gid, _ := strconv.Atoi(name[1])
		vrfMap[name[0]] = uint32(gid)
	}
	s.SetL3NetworkMap(vrfMap)

	waitGroup.Go(func() error {
		err := dpuListener.Start()
		if err != nil {
			return fmt.Errorf("DPU listener failed: %w", err)
		}
		return nil
	})

	waitGroup.Go(func() error {
		// Setting up agent local state
		if Config.EnableNXOS {
			err := agwAgent.Setup(ctx, cancel)
			if err != nil {
				return fmt.Errorf("FWAgent setup failed: %w", err)
			}
		}
		return nil
	})

	// Setup callback to yell if DPUs are out of sync
	waitGroup.Go(func() error {
		agwAgent.DpuHealthCheck(ctx)
		return nil
	})

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
		// Wait for agent token to be ready before proceeding
		var token string
		if Config.K8sServiceAccountAuth != "" {
			token = Config.K8sServiceAccountAuth
			// Set the initial k8s auth token to NXOS if provided via command line option.
			if err := agwAgent.SetK8sCtlrAuthToken(ctx, Config.K8sServiceAccountAuth); err != nil {
				return fmt.Errorf("agw: failed to set agent token: %w", err)
			}
		} else {
			if Config.EnableNXOS {
				// Load the auth from file.
				// If auth is empty, the agent will wait for NXOS to provide the token
				// before starting the k8s controller.
				var err error
				token, err = agwAgent.LoadK8sAuth(ctx)
				if err != nil {
					return fmt.Errorf("failed to wait for agent token: %w", err)
				}
			} else {
				logger.GetLogger().Error("k8s auth token can be provided via --k8s-service-account-auth when NXOS integration is disabled")
			}
		}

		// Set up k8s client configuration in enterpriseOption.Config.
		// Ensure that Config.K8sServiceAccountAuth and enterpriseOption.Config.K8sServiceAccountAuth remain compatible.
		conf.K8sConfig = enterpriseConf.K8sConfig
		if err := setK8sServiceAccountAuth(token); err != nil {
			logger.GetLogger().Error("failed to set K8sServiceAccountAuth value")
		}

		// Set the retry attempt, so manager will retry until successful connection
		// to the k8s control plane.
		conf.K8sConfigRetry = enterpriseConf.K8sConfigRetry

		// Initialize and connect to K8s controller manager
		logger.GetLogger().Info("initializing Kubernetes Manager for on-prem deployment")
		kubernetesManager := manager.Get()
		if kubernetesManager == nil {
			return fmt.Errorf("kubernetes manager not created")
		}
		// Set the register status to ok for the successful connection.
		agwAgent.RegisterStatus(ctx, true)
		// Start the K8s controller manager
		logger.GetLogger().Info("starting Kubernetes Manager for on-prem deployment")
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

	return waitGroup.Wait()
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

func cliServer(ctx context.Context, agwAgent *agw.AgentGateway) error {
	serverPath := agwctl.CLI_SOCK

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
		logger.GetLogger().Info("Context done, shutting down CLI server")
		listener.Close()
	}()

	logger.GetLogger().Info("CLI server listening", "path", serverPath)

	isCtxDone := func(ctx context.Context) bool {
		select {
		case <-ctx.Done():
			logger.GetLogger().Info("Context done, shutting down CLI server")
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

		msg, err := agwctl.Handler(ctx, agwAgent, rxJson)
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
