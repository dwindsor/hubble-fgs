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
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/tetragon/pkg/watcher/conf"
	isovalentcom "github.com/isovalent/ipa/k8s/apis/isovalent.com"
	ipav1alpha1 "github.com/isovalent/ipa/k8s/apis/isovalent.com/v1alpha1"
	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
	"golang.org/x/sync/errgroup"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/manager"

	"github.com/isovalent/hubble-fgs/pkg/agw"
	"github.com/isovalent/hubble-fgs/pkg/commands/agwctl"
	"github.com/isovalent/hubble-fgs/pkg/config"
	"github.com/isovalent/hubble-fgs/pkg/config/library"
	"github.com/isovalent/hubble-fgs/pkg/model/switchevents"
	"github.com/isovalent/hubble-fgs/pkg/model/switchmetrics"
	"github.com/isovalent/hubble-fgs/pkg/model/switchpolicy"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/shutdown"
	enterpriseConf "github.com/isovalent/hubble-fgs/pkg/watcher/conf"
)

const (
	// ConfigMap is the name of the ConfigMap that the agent watches for configuration updates
	TimescapeConfigMapName = "smartswitch-timescape-config"
)

func RunOnPrem(ctx context.Context, agwAgent *agw.AgentGateway, dpuListener *switchpolicy.DPUListener) error {
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
			err := agwAgent.Setup(ctx)
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
			err := switchpolicy.AddFromFile(f, agwAgent.PolicyHandler)
			if err != nil {
				return fmt.Errorf("add SmartSwitchNetworkPolicy failed: %w", err)
			}
		}
	}

	// Add Network Policy Dir
	if Config.NetworkPoliciesDir != "" {
		err := switchpolicy.AddFromDir(Config.NetworkPoliciesDir, agwAgent.PolicyHandler)
		if errors.Is(err, fs.ErrNotExist) {
			logger.GetLogger().Info("smartSwitchNetworkPolicy dir does not exist", "network-policy-dir", Config.NetworkPoliciesDir)
		} else if err != nil {
			logger.GetLogger().Error("failed to add smartSwitchNetworkPolicy from dir", "network-policy-dir", Config.NetworkPoliciesDir, logfields.Error, err)
			return fmt.Errorf("add SmartSwitchNetworkPolicy failed: %w", err)
		} else {
			logger.GetLogger().Info("smartSwitchNetworkPolicy dir loaded", "network-policy-dir", Config.NetworkPoliciesDir)
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
			agwAgent.DisableHaWatching(ctx)
		}
	}

	// Setup metrics collector
	metricsCollector := setupMetricsCollector(ctx)

	if Config.EnableKubernetes {
		// Wait for agent token to be ready before proceeding
		var token string
		if Config.K8sServiceAccountAuth != "" {
			token = Config.K8sServiceAccountAuth
			// Set the initial k8s auth token to NXOS if provided via command line option.
			if err := agwAgent.SetK8sCtlrAuthToken(ctx, Config.K8sServiceAccountAuth); err != nil {
				return fmt.Errorf("agw failed to set agent token: %w", err)
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

		// Reset NXOS connection status before starting K8s manager.
		// Set the initial proxy configuration from NXOS.
		if Config.EnableNXOS {
			agwAgent.ResetConnectionStatus(ctx)
			// ignore error here, as proxy may not be needed,
			// or user can still configure later.
			agwAgent.GetNxProxyConfig(ctx)
		}

		// Initialize and connect to K8s controller manager
		logger.GetLogger().Info("initializing Kubernetes Manager for on-prem deployment", "controller-url", agwAgent.Token.K8sControllerURL())
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

		// Start SmartSwitch inventory handler in waitGroup
		if Config.EnableNXOS && agwAgent.InventoryHandler != nil {
			waitGroup.Go(func() error {
				err := agwAgent.InventoryHandler.AddSmartSwitchInventoryCR(ctx, kubernetesManager)
				if err != nil {
					logger.GetLogger().Error("start inventory handler", logfields.Error, err)
					return fmt.Errorf("inventory handler failed: %w", err)
				}
				return nil
			})
		}

		// Start Prometheus pusher in waitGroup
		setupPrometheusPusher(ctx, waitGroup, agwAgent, metricsCollector)

		// Create connection monitor for health checking
		connMonitor := agw.NewConnectionMonitor(agwAgent, Config.EnableNXOS, kubernetesManager, agwAgent.Token.K8sControllerURL())
		// TODO: Wait for configmap to be ready
		ConfigMaps := []string{Config.ConfigMap}

		// Only add Timescape ConfigMap if CLI timescape is disabled (precedence logic)
		// Register the timescape config callback
		library.GetRepository().AddConfigCallback(v1alpha.ConfigType_CONFIG_TYPE_TIMESCAPE, switchevents.SubscribeTimescapeConfig)
		if !Config.TimescapeClientEnable {
			logger.GetLogger().Info("Adding Timescape ConfigMap to informer")
			ConfigMaps = append(ConfigMaps, TimescapeConfigMapName)
			// Set parameters needed for Setup calls from ConfigMap callbacks
			switchevents.SetTimescapeSetupParams(ctx, agwAgent, Config.EnableNXOS, kubernetesManager)
		} else {
			// Start Timescape client using CLI configuration
			if err := switchevents.SetupTimescapeFromCLI(ctx, agwAgent, Config.EnableNXOS,
				Config.TimescapeClientEnable, Config.TimescapePassword, Config.TimescapeEndpoint, kubernetesManager); err != nil {
				library.GetRepository().DeleteConfigCallback(v1alpha.ConfigType_CONFIG_TYPE_TIMESCAPE)
				return err
			}
		}

		err = config.AddConfigMapInformer(ctx, kubernetesManager, ConfigMaps, connMonitor)
		if err != nil {
			logger.GetLogger().Error("configmap informer with connection monitoring failed", logfields.Error, err)
			return err
		}

		if Config.EnableNXOS {
			logger.GetLogger().Debug("Waiting for NXOS to be InService before watching SmartSwitchNetworkPolicy CRD")
			agwAgent.WaitForInService(ctx)
			logger.GetLogger().Debug("Done NXOS InService is configured")
		}

		crds := make(map[string]struct{})
		crds["smartswitchnetworkpolicies"+"."+isovalentcom.GroupName] = struct{}{} // HACK: CRD name should be used from IPA repo
		if len(crds) > 0 {
			err = kubernetesManager.WaitCRDsWithResync(ctx, crds, 120*time.Second)
			if err != nil {
				logger.GetLogger().Error("failed to wait smartswitch policy crd", logfields.Error, err)
				// Trigger agw restart to retry CRD wait
				shutdown.TriggerShutdown(shutdown.RestartExitCode)
				return nil
			}
		}

		policyStatusHandler := switchevents.GetGlobalPolicyStatusHandler()
		networkpolicyWatcher, err := switchpolicy.AddSmartSwitchNetworkPolicyInformer(ctx, kubernetesManager, agwAgent.PolicyHandler, policyStatusHandler, metricsCollector)
		if err != nil {
			logger.GetLogger().Error("failed to watch smartswitch policy crd", logfields.Error, err)
			return err
		}

		// Store the watcher globally so timescape client can update its policy status handler when initialized
		switchevents.SetGlobalNetworkPolicyWatcher(networkpolicyWatcher)
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

// setupMetricsCollector initializes the metrics collector and starts any enabled metrics integrations
func setupMetricsCollector(ctx context.Context) *switchmetrics.MetricsCollector {
	// Initialize metrics collector singleton
	// The metrics collector is still needed for agwctl show, as it provides
	// process-level metrics and policy/rule counts.
	metricsCollector := switchmetrics.GetInstance(ctx)
	if metricsCollector == nil {
		logger.GetLogger().Error("failed to set up metrics collector")
		return nil
	}

	return metricsCollector
}

// setupPrometheusPusher validates Prometheus configuration and starts the Prometheus pusher
func setupPrometheusPusher(ctx context.Context, waitGroup *errgroup.Group, agwAgent *agw.AgentGateway, metricsCollector *switchmetrics.MetricsCollector) error {
	if metricsCollector == nil {
		logger.GetLogger().Error("metrics collector is nil, cannot start Prometheus pusher")
		return nil
	}

	// Setup Prometheus pusher if enabled
	if !Config.PrometheusClientEnable {
		logger.GetLogger().Info("prometheus client not enabled, skipping setup")
		return nil
	}
	// Validate required prometheus configuration
	trimmedUsername := strings.TrimSpace(Config.PrometheusUsername)
	if trimmedUsername == "" {
		logger.GetLogger().Error("prometheus client enabled but username not configured", "flag", "--prometheus-username")
		return nil
	}

	trimmedPassword := strings.TrimSpace(Config.PrometheusPassword)
	if trimmedPassword == "" {
		logger.GetLogger().Error("prometheus client enabled but password not configured", "flag", "--prometheus-password")
		return nil
	}

	trimmedEndpoint := strings.TrimSpace(Config.PrometheusEndpoint)
	if trimmedEndpoint == "" {
		logger.GetLogger().Error("prometheus client enabled but endpoint not configured", "flag", "--prometheus-endpoint")
		return nil
	}

	serialNumber := "smartswitch-unknown"
	if agwAgent != nil && Config.EnableNXOS {
		// Set the switch serial number label for metrics if NXOS is enabled
		serialNumber = agwAgent.GetSerialNumber(ctx)
	}

	waitGroup.Go(func() error {
		metricsConfig := switchmetrics.DefaultPrometheusPushConfig()
		metricsConfig.SetControllerURL(trimmedEndpoint)
		metricsConfig.SetUsername(trimmedUsername)
		metricsConfig.SetPassword(trimmedPassword)
		metricsConfig.SetSwitchSerialNumber(serialNumber)

		if err := metricsCollector.StartPrometheusPusher(ctx, metricsConfig); err != nil {
			logger.GetLogger().Error("metrics pusher exited with error; continuing without metrics", "error", err)
		}

		return nil
	})

	return nil
}
