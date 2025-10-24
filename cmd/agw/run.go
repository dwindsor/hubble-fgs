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

	"github.com/cilium/tetragon/pkg/watcher/conf"
	ipav1alpha1 "github.com/isovalent/ipa/k8s/apis/isovalent.com/v1alpha1"
	"golang.org/x/sync/errgroup"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/manager"

	"github.com/isovalent/hubble-fgs/pkg/agw"
	"github.com/isovalent/hubble-fgs/pkg/commands/agwctl"
	"github.com/isovalent/hubble-fgs/pkg/config"
	"github.com/isovalent/hubble-fgs/pkg/model/server/dpu"
	"github.com/isovalent/hubble-fgs/pkg/model/switchpolicy"
	"github.com/isovalent/hubble-fgs/pkg/netpol"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	enterpriseConf "github.com/isovalent/hubble-fgs/pkg/watcher/conf"
)

func RunOnPrem(ctx context.Context, cancel context.CancelFunc, agwAgent *agw.AgentGateway, dpuListener *dpu.DPUListener) error {
	logger.GetLogger().Info("Agent starting", "config", redactedConfig())
	waitGroup, ctx := errgroup.WithContext(ctx)

	// Vrf mapping if provided using CLI
	vrfMap := switchpolicy.NewL3Networks()
	for _, nameGID := range Config.VrfMap {
		name := strings.Split(nameGID, ":")
		if len(name) < 2 {
			logger.GetLogger().Error("invalid value passed in vrfmap", "vrf", nameGID)
			continue
		}
		gid, err := strconv.Atoi(name[1])
		if err != nil {
			logger.GetLogger().Error("invalid id passed in vrfmap", logfields.Error, err, "vrf", nameGID)
			continue
		}
		vrfName := switchpolicy.VrfName(name[0])
		vrfId := switchpolicy.VrfGID(gid)
		err = vrfMap.Add(vrfName, vrfId)
		if err != nil {
			logger.GetLogger().Error("failed to add vrf to vrfmap", logfields.Error, err, "vrf", nameGID)
		}
	}
	err := agwAgent.PolicyHandler.SetL3Networks(vrfMap)
	if err != nil {
		logger.GetLogger().Error("failed to set CLI configured vrfmap", logfields.Error, err, "vrfmap", Config.VrfMap)
	}

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

	// Determine if NXOS is in headless mode
	if Config.EnableKubernetes {
		// Get the headless mode status from NXOS
		// If NXOS is in headless mode, disable Kubernetes control plane
		headless := agwAgent.GetNxHeadlessMode()
		if headless {
			logger.GetLogger().Info("NXOS is in headless mode, disabling Kubernetes control plane")
			Config.EnableKubernetes = false
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
				logger.GetLogger().Warn("k8s auth token can be provided via --k8s-service-account-auth when NXOS integration is disabled")
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

		// Set the nxos register status to ok for the successful connection.
		if Config.EnableNXOS {
			agwAgent.RegisterStatus(ctx, true)
		}

		// Start the K8s controller manager
		logger.GetLogger().Info("starting Kubernetes Manager for on-prem deployment")
		utilruntime.Must(ipav1alpha1.AddToScheme(kubernetesManager.Manager.GetScheme()))
		kubernetesManager.Start(ctx)

		// TODO: Wait for configmap to be ready
		err := config.AddConfigMapInformer(ctx, kubernetesManager)
		if err != nil {
			logger.GetLogger().Error("configmap failed")
			return err
		}

		crds := make(map[string]struct{})
		crds["smartswitchnetworkpolicies"+"."+ipav1alpha1.GroupVersion.Group] = struct{}{} // HACK: CRD name should be used from IPA repo
		if len(crds) > 0 {
			err = kubernetesManager.WaitCRDs(ctx, crds)
			if err != nil {
				return err
			}
		}
		err = switchpolicy.AddSmartSwitchNetworkPolicyInformer(ctx, kubernetesManager, agwAgent.PolicyHandler)
		if err != nil {
			logger.GetLogger().Error("failed to watch smartswitch policy crd", logfields.Error, err)
			return err
		}
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
