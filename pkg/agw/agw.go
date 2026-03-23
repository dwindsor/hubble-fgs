// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package agw

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/version"

	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
	"google.golang.org/protobuf/proto"

	"github.com/isovalent/hubble-fgs/pkg/config"
	"github.com/isovalent/hubble-fgs/pkg/config/library"
	"github.com/isovalent/hubble-fgs/pkg/dpu/policy"
	"github.com/isovalent/hubble-fgs/pkg/ipc"
	"github.com/isovalent/hubble-fgs/pkg/logexport"
	"github.com/isovalent/hubble-fgs/pkg/model/switchpolicy"
	"github.com/isovalent/hubble-fgs/pkg/model/switchstatus"
	"github.com/isovalent/hubble-fgs/pkg/mtls"
	"github.com/isovalent/hubble-fgs/pkg/nxos"
	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi/mock"
	"github.com/isovalent/hubble-fgs/pkg/nxos/store/device"
	nxtypes "github.com/isovalent/hubble-fgs/pkg/nxos/types"
	"github.com/isovalent/hubble-fgs/pkg/shutdown"
	"github.com/isovalent/hubble-fgs/pkg/token"
)

const (
	BUFSIZE        = 4096
	TOKEN_INTERVAL = 2
	CHECK_INTERVAL = 3 // in second

	// dpuTimeout = 300 // in second
)

func NewAgent(dpuListener *switchpolicy.DPUListener, policyHandler switchpolicy.PolicyHandler, enableNXOS bool, nxosManager nxos.Manager) *AgentGateway {
	mac := os.Getenv("NX_SAS_RMAC")
	hostname := os.Getenv("CAF_SYSTEM_NAME")
	startupTime := time.Now()

	logger.GetLogger().Info("Agent started", "mac", mac, "hostname", hostname, "startup_time", startupTime.Format(time.RFC3339))

	// DPU ports
	lowStr, ok := os.LookupEnv("NX_DPU_PORT_START")
	if !ok {
		lowStr = "28672"
	}
	dpuLow, _ := strconv.Atoi(lowStr)
	highStr, ok := os.LookupEnv("NX_DPU_PORT_END")
	if !ok {
		highStr = "29695"
	}
	dpuHigh, _ := strconv.Atoi(highStr)

	// AGW ports
	lowStr, ok = os.LookupEnv("NX_HSA_PORT_START")
	if !ok {
		lowStr = "28672"
	}
	cpaLow, _ := strconv.Atoi(lowStr)
	highStr, ok = os.LookupEnv("NX_HSA_PORT_END")
	if !ok {
		highStr = "29695"
	}
	cpaHigh, _ := strconv.Atoi(highStr)

	// Adding config callbacks
	library.GetRepository().AddConfigCallback(v1alpha.ConfigType_CONFIG_TYPE_DPU, dpuListener.SubscribeDpuConfig)
	library.GetRepository().AddConfigCallback(v1alpha.ConfigType_CONFIG_TYPE_LOG_SYSLOG, dpuListener.SubscribeConfig)
	library.GetRepository().AddConfigCallback(v1alpha.ConfigType_CONFIG_TYPE_LOG_TIMESCAPE, dpuListener.SubscribeConfig)
	library.GetRepository().AddConfigCallback(v1alpha.ConfigType_CONFIG_TYPE_LOG_SPLUNK, dpuListener.SubscribeConfig)
	library.GetRepository().AddConfigCallback(v1alpha.ConfigType_CONFIG_TYPE_HA, dpuListener.SubscribeHaConfig)
	library.GetRepository().AddConfigCallback(v1alpha.ConfigType_CONFIG_TYPE_NETWORK, dpuListener.SubscribeConfig)

	// Setting up dpu config atomically
	// dpuConfig.ServiceIp is populated by nxos package
	// dpuConfig.HaIp is populated by nxos package
	err := library.GetRepository().UpdateConfig(v1alpha.ConfigType_CONFIG_TYPE_DPU, func(existing *v1alpha.ConfigObject) (*v1alpha.ConfigObject, error) {
		var dpuConfig *v1alpha.DpuConfig
		if existing != nil && existing.GetConfigDpu() != nil {
			dpuConfig = proto.Clone(existing.GetConfigDpu()).(*v1alpha.DpuConfig)
		} else {
			dpuConfig = &v1alpha.DpuConfig{}
		}
		dpuConfig.ServiceMac = mac
		dpuConfig.SwitchName = hostname
		dpuConfig.PortLow = uint32(dpuLow)
		dpuConfig.PortHigh = uint32(dpuHigh)
		return &v1alpha.ConfigObject{
			Type:   v1alpha.ConfigType_CONFIG_TYPE_DPU,
			Source: v1alpha.ConfigSource_CONFIG_SOURCE_LOCAL,
			Config: &v1alpha.ConfigObject_ConfigDpu{ConfigDpu: dpuConfig},
		}, nil
	})
	if err != nil {
		logger.GetLogger().Error("Failed to update dpu config", "error", err)
	}

	agw := &AgentGateway{
		Cfg:           &config.Config{},
		Token:         token.GetAgentToken(),
		MTLS:          mtls.GetMTLSCertificates(),
		StartupTime:   startupTime,
		serviceMac:    mac,
		dpuPortLow:    uint16(dpuLow),
		dpuPortHigh:   uint16(dpuHigh),
		cpaPortLow:    uint16(cpaLow),
		cpaPortHigh:   uint16(cpaHigh),
		enableNXOS:    enableNXOS,
		nxosManager:   nxosManager,
		dpuListener:   dpuListener,
		PolicyHandler: policyHandler,
	}

	// Initialize the inventory handler with callback functions (no circular reference)
	agw.InventoryHandler = switchstatus.NewInventoryHandler(
		switchstatus.InventoryDataProvider{
			GetDPUStatus: func() ([]switchpolicy.DPUReportStatus, error) {
				return agw.dpuListener.GetDPUStatus()
			},
			GetK8sNamespace: func() string {
				if agw.Token == nil {
					return ""
				}
				return agw.Token.K8sNamespace()
			},
			GetServiceMAC: func() string {
				return agw.serviceMac
			},
			GetServiceIP: func() string {
				return agw.nxosManager.DeviceStore().ServiceIP()
			},
			GetDeviceConnectionStatus: func() string {
				return agw.nxosManager.DeviceStore().ConnectionStatus()
			},
			GetSerialNum: func(_ context.Context) string {
				return agw.nxosManager.DeviceStore().SerialNumber()
			},
		},
	)

	return agw
}

type AgentGateway struct {
	AgentId      string
	Name         string
	Ip           string
	Hostname     string
	Architecture string
	Os           string
	SerialNumber string
	StartupTime  time.Time // Timestamp when AGW was started

	Cfg   *config.Config
	Token *token.AgentToken
	MTLS  *mtls.MTLSCertificates

	serviceMac  string
	dpuPortLow  uint16
	dpuPortHigh uint16
	cpaPortLow  uint16
	cpaPortHigh uint16
	enableNXOS  bool // Flag to enable/disable NXOS integration

	nxosManager      nxos.Manager // NXOS manager instance
	dpuListener      *switchpolicy.DPUListener
	PolicyHandler    switchpolicy.PolicyHandler
	InventoryHandler switchstatus.InventoryHandler

	sync.RWMutex
}

func (agw *AgentGateway) Id() string {
	return agw.AgentId
}

// NxosManager returns the NXOS manager instance.
func (agw *AgentGateway) NxosManager() nxos.Manager {
	return agw.nxosManager
}

func (agw *AgentGateway) Version() string {
	if version.Version == "" {
		return "dev"
	}
	return version.Version
}

func (agw *AgentGateway) SkipAuth() bool {
	return agw.Cfg.Env.SkipAuth
}

func (agw *AgentGateway) KeepAliveInterval() int {
	return agw.Cfg.Agent.KeepAliveInterval
}

// GetPort returns a port within the CPA port range for the specified service type
func (agw *AgentGateway) GetPort(serviceType ServicePortType) uint16 {
	offset, err := GetServicePortOffset(serviceType)
	if err != nil {
		logger.GetLogger().Warn("Unknown service type for port allocation", "service_type", serviceType, "error", err)
		return agw.cpaPortLow
	}
	if (agw.cpaPortLow + offset) > agw.cpaPortHigh {
		logger.GetLogger().Warn("Requested port for service exceeds CPA port range", "service_type", serviceType)
	}
	return agw.cpaPortLow + offset
}

// Get preferred outbound ip of this machine
func getOutboundIP() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP.String(), nil
}

func (agw *AgentGateway) Config(_ context.Context, path string) error {
	// Collecting agent metadata
	var err error
	agw.Ip, err = getOutboundIP()
	if err != nil {
		logger.GetLogger().Error("Failed to get machine IP address", logfields.Error, err)
	}
	agw.Hostname, err = os.Hostname()
	if err != nil {
		logger.GetLogger().Error("Failed to get machine hostname", logfields.Error, err)
	}
	agw.Architecture = runtime.GOARCH
	agw.Os = runtime.GOOS

	// Setting up config
	created, err := agw.Cfg.Init(path)
	if err != nil {
		logger.GetLogger().Error("Failed to initialize config", logfields.Error, err)
		return err
	}
	if created {
		logger.GetLogger().Info("Config file not found, new config file created", "path", path)
	} else {
		logger.GetLogger().Info("Config file found", "path", path)
	}

	agw.AgentId = agw.Cfg.Agent.AgentId
	// HACK for cpa container scheduling/resource issue
	agw.Cfg.Agent.KeepAliveInterval = 10

	// Initialize mTLS certificate path after config is loaded
	agw.InitializeMTLS()

	return nil
}

// GetDPUListener returns the DPU (Data Processing Unit) listener associated with
// the AgentGateway.
func (agw *AgentGateway) GetDPUListener() *switchpolicy.DPUListener {
	return agw.dpuListener
}

func (agw *AgentGateway) GetNxHeadlessMode() bool {
	return agw.nxosManager.DeviceStore().IsHeadlessMode()
}

// DisableHaWatching disables HA store watching in headless mode.
func (agw *AgentGateway) DisableHaWatching(_ context.Context) {
	logger.GetLogger().Info("HA watching disabled (headless mode)")
}

func (agw *AgentGateway) GetDeviceConnectionStatus() string {
	return agw.nxosManager.DeviceStore().ConnectionStatus()
}

func (agw *AgentGateway) GetSerialNumber(_ context.Context) string {
	if agw.SerialNumber == "" {
		return agw.nxosManager.DeviceStore().SerialNumber()
	}
	return agw.SerialNumber
}

func (agw *AgentGateway) Setup(ctx context.Context) error {
	err := agw.nxosManager.Setup(ctx)
	if err != nil {
		// Removed GetLogger().Fatal to avoid immediate termination, use shutdown manager.
		logger.GetLogger().Error("NXOS setup failed", "error", err)
		shutdown.TriggerShutdown(shutdown.ErrorExitCode)
		return err
	}

	return nil
}

func (agw *AgentGateway) RegisterStatus(ctx context.Context, status bool) {
	logger.GetLogger().Debug("Setting registration status", "status", status)
	agw.nxosManager.DeviceStore().ResetRegistration(ctx)
	if !status {
		agw.nxosManager.DeviceStore().SetAdmissionStatus(ctx, device.CommonStateFailure, nxos.RegFailK8sAuth)
		agw.nxosManager.DeviceStore().SetSkipReg(ctx, true, nxos.RegFailK8sAuth)
		agw.nxosManager.SetConnFail(ctx, nxos.ConnFailed)
	} else {
		agw.nxosManager.DeviceStore().SetAdmissionStatus(ctx, device.CommonStateSuccess, nxos.RegOk)
		agw.nxosManager.SetConnOk(ctx, nxos.ConnOk)
	}
}

func (agw *AgentGateway) ResetConnectionStatus(ctx context.Context) {
	agw.nxosManager.DeviceStore().ResetConnection(ctx)
}

func (agw *AgentGateway) SetConnectionStatus(ctx context.Context, status bool, nxosMode bool) {
	logger.GetLogger().Debug("Setting connection status", "status", status)
	if !nxosMode {
		// Running in non-NXOS mode.
		return
	}

	if status {
		agw.nxosManager.SetConnOk(ctx, nxos.ConnOk)
	} else {
		agw.nxosManager.SetConnFail(ctx, nxos.ConnFailed)
	}

	agw.notifyHA(ctx, status)
}

// notifyHA notifies the high availability system about
// the controller connection current status.
func (agw *AgentGateway) notifyHA(ctx context.Context, status bool) {
	agw.nxosManager.NotifyPolicyCheck(ctx, status)
}

// SetK8sCtlrAuthToken sets the Kubernetes controller authentication token in both the AgentToken and Nxos structs,
// and persists the token if possible. Returns an error if the operation fails.
// This function is invoked when the user provides a token in agw command line option, which takes precedence.
func (agw *AgentGateway) SetK8sCtlrAuthToken(ctx context.Context, token string) error {
	logger.GetLogger().Debug("setting k8s auth token")

	if agw.Token != nil {
		// Set the token path if not already set.
		if agw.Cfg.Env.TokenPath == "" {
			return fmt.Errorf("config TokenPath is not set")
		} else if agw.Cfg.Env.TokenPath != agw.Token.K8sAuthPath() {
			agw.Token.SetK8sAuthPath(agw.Cfg.Env.TokenPath)
		}
	} else {
		return fmt.Errorf("failed to set AgentToken")
	}
	// Set the token in both the AgentToken and Nxos structs.
	// Ignore restart request from DeviceStore.SetToken, since token is set via agw command line.
	_, err := agw.nxosManager.DeviceStore().SetToken(ctx, token)
	if err != nil {
		return err
	}

	return nil
}

// LoadK8sAuth retrieves the Kubernetes authentication token from NXOS,
// waiting if necessary until the token is available or the context is canceled.
// Returns the token string if successful, or an error if the wait fails or the token remains unavailable.
func (agw *AgentGateway) LoadK8sAuth(ctx context.Context) (string, error) {
	logger.GetLogger().Debug("getting or waiting for K8s auth token from switch")

	ok, err := agw.LoadAuth(ctx)
	if err != nil {
		return "", err
	}
	var token string
	if ok {
		logger.GetLogger().Info("token ready")
		// Cache the token after waiting to avoid redundant calls.
		token = agw.Token.K8sAuthToken()
		if token == "" {
			return "", fmt.Errorf("token is still empty after waiting")
		}
		return token, nil
	}

	return "", fmt.Errorf("token was not loaded")
}

// LoadAuth attempts to load authentication data for the AgentGateway.
// It sets the Kubernetes authentication token path from the configuration,
// then tries to load from multiple sources in order:
// 1. Controller store (token received via gNMI from NXOS)
// 2. Token file on disk
// 3. Environment variable
// If no token is immediately available, it watches for token changes from the
// controller store via gNMI notifications. The function returns true if
// authentication data is loaded successfully, or false and an error otherwise.
func (agw *AgentGateway) LoadAuth(ctx context.Context) (bool, error) {
	logger.GetLogger().Debug("loading authentication data")
	// Setting token path.
	if agw.Cfg.Env.TokenPath != "" {
		agw.Token.SetK8sAuthPath(agw.Cfg.Env.TokenPath)
	} else {
		return false, fmt.Errorf("config TokenPath is empty")
	}

	// First, check if token is already available in the controller store (from gNMI/persistence)
	if token := agw.nxosManager.DeviceStore().Token(); token != "" {
		logger.GetLogger().Info("Token found in controller store")
		if err := agw.Token.ValidK8sAuth(token); err == nil {
			if err := agw.Token.SetAndPersistK8sAuthToken(token); err != nil {
				logger.GetLogger().Warn("Failed to persist token from controller store", "error", err)
			}
			return true, nil
		}
		logger.GetLogger().Warn("Token in controller store is invalid, trying other sources")
	}

	// Finding and setting Token.
	registered := make(chan bool, 1)

	// Subscribe to controller store for token changes via gNMI
	tokenReceived := make(chan string, 1)
	unsubscribe := agw.nxosManager.DeviceWatcher().Watch(func(event device.Event) {
		if event.Type == device.EventTokenChanged {
			token := agw.nxosManager.DeviceStore().Token()
			if token != "" {
				logger.GetLogger().Info("Token received via gNMI notification")
				select {
				case tokenReceived <- token:
				default:
				}
			}
		}
	})
	defer unsubscribe()

	go func() {
		// Try getting authentication from file/env immediately first
		reg, err := agw.tryLoadK8sAuth()
		if err == nil {
			select {
			case registered <- reg:
			default:
			}
			return
		}

		// Then enter the retry loop with delays
		for {
			select {
			case <-ctx.Done():
				logger.GetLogger().Debug("Context canceled while trying to load K8s auth")
				return
			case <-time.After(TOKEN_INTERVAL * time.Second):
				reg, err := agw.tryLoadK8sAuth()
				if err == nil {
					select {
					case registered <- reg:
					default:
					}
					return
				}
			}
		}
	}()

	// Waiting for tokens to be loaded from any source.
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case reg := <-registered:
		return reg, nil
	case token := <-tokenReceived:
		// Token received via gNMI from controller store
		if err := agw.Token.ValidK8sAuth(token); err != nil {
			logger.GetLogger().Error("Token from gNMI is invalid", "error", err)
			return false, err
		}
		if err := agw.Token.SetAndPersistK8sAuthToken(token); err != nil {
			logger.GetLogger().Warn("Failed to persist token from gNMI", "error", err)
		}
		return true, nil
	}
}

func (agw *AgentGateway) tryLoadK8sAuth() (bool, error) {
	// Try loading the token
	valid, err := agw.Token.Load()
	if err != nil {
		logger.GetLogger().Error("failed to load tokens from file", logfields.Error, err)
		return false, err
	}

	if !valid {
		logger.GetLogger().Info("token file missing, getting K8sAuth from environment")
		err = agw.Token.LoadK8sAuthFromEnv()
		if err != nil {
			logger.GetLogger().Error("failed to get K8sAuth from environment",
				logfields.Error, err)
			return false, err
		}
	}

	logger.GetLogger().Debug("token parsed and validated successfully")
	if agw.Token != nil {
		// Set the token path if not already set.
		if agw.Cfg.Env.TokenPath == "" {
			return false, fmt.Errorf("config TokenPath is empty")
		} else if agw.Cfg.Env.TokenPath != agw.Token.K8sAuthPath() {
			agw.Token.SetK8sAuthPath(agw.Cfg.Env.TokenPath)
		}
		// Persist the token.
		if err := agw.Token.Persist(); err != nil {
			return false, err
		}
	}

	if err := agw.Cfg.Reload(); err != nil {
		logger.GetLogger().Error("failed to reload config", logfields.Error, err)
		return false, err
	}
	return true, nil
}

// InitializeMTLS initializes the mutual TLS (mTLS) configuration for the AgentGateway.
//
// Returns true if mTLS initialization is successful, false otherwise.
// Logs appropriate error messages when initialization fails due to:
// - Uninitialized MTLS certificates handler
// - Missing or empty mTLS path configuration
// - Failure to configure the certificate path
func (agw *AgentGateway) InitializeMTLS() bool {
	if agw.MTLS == nil {
		logger.GetLogger().Error("mTLS certificates handler not initialized")
		return false
	}

	if agw.Cfg == nil || agw.Cfg.Env.MTLSPath == "" {
		logger.GetLogger().Error("mTLS path is not configured in AGW config")
		return false
	}

	// Configure the mTLS path from config using the mtls package function
	if err := agw.MTLS.ConfigureCertificatePath(agw.Cfg.Env.MTLSPath); err != nil {
		logger.GetLogger().Error("failed to configure mTLS certificate path",
			logfields.Error, err,
			"configuredPath", agw.Cfg.Env.MTLSPath)
		return false
	}

	return true
}

func (agw *AgentGateway) WaitForInService(ctx context.Context) {
	logger.GetLogger().Debug("WaitForInService")

	for {

		if agw.nxosManager.DeviceStore().IsInService() {
			logger.GetLogger().Debug("Now is InService")
			return
		}

		select {
		case <-ctx.Done():
			logger.GetLogger().Debug("Context done in WaitForInService")
			return

		case <-time.After(CHECK_INTERVAL * time.Second):
		}
	}
}

func (agw *AgentGateway) GetStartupTime() time.Time {
	return agw.StartupTime
}

// GetNumDpu returns the number of DPUs from NXOS
func (agw *AgentGateway) GetNumDpu() int {
	return agw.nxosManager.DPUStore().DpuCount()
}

// --------------------- DPU related
func (agw *AgentGateway) DpuHealthCheck(ctx context.Context) {
	retries := 0
	maxRetries := 6
	healthCheckTimer := 10 * time.Second

	for {
		select {
		case <-ctx.Done():
			logger.GetLogger().Info("Stop DPU health checker")
			return
		case <-time.After(healthCheckTimer):
			logger.GetLogger().Debug("DPU health check - starting", logexport.Export)
			ok := agw.dpuListener.StateCheck()
			if !ok {
				retries++
				if retries > maxRetries {
					agw.nxosManager.DpuInSync(ctx, false)
					logger.GetLogger().Error("DPU out of sync!")
				}
			} else {
				agw.nxosManager.DpuInSync(ctx, true)
				retries = 0
			}
			ok, cnt := agw.dpuListener.HealthCheck()
			agw.nxosManager.DpuHealth(ctx, ok, cnt)
		}
	}
}

func (agw *AgentGateway) PoliciesAdd(_ context.Context, msgData ipc.MessageData) string {
	filePath := msgData.Flags["file"]
	logger.GetLogger().Debug("Add policies", "file", filePath)

	// Adding policies from file
	err := switchpolicy.AddFromFile(filePath, agw.PolicyHandler)
	if err != nil {
		return fmt.Sprintf("Failed to add policies from file: %v", err)
	}
	return "Policies added successfully"
}

func (agw *AgentGateway) PoliciesRemove(_ context.Context, msgData ipc.MessageData) string {
	var resourceID string
	if len(msgData.Args) >= 1 {
		resourceID = msgData.Args[0]
	}
	filePath := msgData.Flags["file"]
	logger.GetLogger().Debug("Remove policies", "file", filePath, "resourceID", resourceID)

	// Passing resourceID argument has precedence to file flag, so checking for it first
	if resourceID != "" {
		values := strings.Split(resourceID, "/")
		if len(values) != 3 {
			return fmt.Sprintf("invalid resourceID format: %s", resourceID)
		}
		rid := switchpolicy.NewResourceID(values[0], values[1], values[2])
		err := agw.PolicyHandler.DeletePolicy(rid, "")
		if err != nil {
			return fmt.Sprintf("Failed to remove policy %s: %v", resourceID, err)
		}
		return "Policy " + resourceID + " removed successfully"
	}

	// Removing policies from file
	err := switchpolicy.DeleteFromFile(filePath, agw.PolicyHandler)
	if err != nil {
		return fmt.Sprintf("Failed to remove policies from file: %v", err)
	}
	return "Policies removed successfully"
}

func (agw *AgentGateway) PoliciesShow(_ context.Context, msgData ipc.MessageData) string {
	nameFilter := msgData.Flags["filter"]
	logger.GetLogger().Debug("Show policies", "nameFilter", nameFilter)

	// Filter policies by name pattern
	policyMap := agw.PolicyHandler.ListPolicies()
	var policyNames []string
	for resourceId := range policyMap {
		policyNames = append(policyNames, resourceId.String())
	}
	filteredNames := filterPolicyNames(policyNames, nameFilter)

	if len(filteredNames) == 0 {
		if msgData.Flags["json"] == "true" {
			return "{}"
		}
		return formatNoPoliciesMessage(nameFilter)
	}

	// If checking if the json flag was passed, so that policy can be formatted correctly
	if msgData.Flags["json"] == "true" {
		result := formatSwitchPoliciesJsonStringByName(filteredNames, policyMap)
		return result
	}

	// Text output only
	var result strings.Builder
	result.WriteString(formatSummaryHeader(len(filteredNames), nameFilter))

	// Iterate over filtered policy names and get each policy from the policyMap
	for resourceId, rulesList := range policyMap {
		policyName := resourceId.String()
		// Check if this policy matches the filter
		isFiltered := false
		for _, filteredName := range filteredNames {
			if policyName == filteredName {
				isFiltered = true
				break
			}
		}
		if !isFiltered {
			continue
		}
		result.WriteString(formatSwitchPolicy(resourceId, rulesList))
	}
	return result.String()
}

func (agw *AgentGateway) ConfigShow(_ context.Context, msgData ipc.MessageData) string {
	logger.GetLogger().Debug("Show config")

	// Get all config objects from the config repository
	configObjects := library.GetRepository().GetConfigObjects()

	if len(configObjects) == 0 {
		if msgData.Flags["json"] == "true" {
			return "{}"
		}
		return "No configuration found"
	}

	// If checking if the json flag was passed, so that config can be formatted correctly
	if msgData.Flags["json"] == "true" {
		result, err := json.Marshal(configObjects)
		if err != nil {
			return fmt.Sprintf("Error marshalling config: %v", err)
		}
		return string(result)
	}

	// Text output only
	var result strings.Builder
	result.WriteString(fmt.Sprintf("Configuration Objects: %d\n", len(configObjects)))
	result.WriteString(strings.Repeat("-", 40) + "\n")

	for configType, configObj := range configObjects {
		result.WriteString(fmt.Sprintf("Type: %s\n", configType.String()))
		configJson, err := json.MarshalIndent(configObj, "  ", "  ")
		if err != nil {
			result.WriteString(fmt.Sprintf("  Error: %v\n", err))
		} else {
			result.WriteString(fmt.Sprintf("  %s\n", string(configJson)))
		}
		result.WriteString("\n")
	}
	return result.String()
}

func (agw *AgentGateway) PoliciesClear(_ context.Context) error {
	logger.GetLogger().Warn("Clearing all policies")

	policies := agw.PolicyHandler.ListPolicies()
	for r := range policies {
		err := agw.PolicyHandler.DeletePolicy(r, "")
		if err != nil {
			return err
		}
	}
	return nil
}

func (agw *AgentGateway) PoliciesInfo(_ context.Context, msgData ipc.MessageData) string {
	logger.GetLogger().Debug("Policies info")

	type PolicySummary struct {
		ResourceVersion   string         `json:"resource_version"`
		TotalPolicies     int            `json:"total_policies"`
		TotalRules        int            `json:"total_rules"`
		ActiveRules       int            `json:"active_rules"`
		AllowRules        int            `json:"allow_rules"`
		DenyRules         int            `json:"deny_rules"`
		TotalPolicyVRFs   int            `json:"total_policy_vrfs"`
		ActivePolicyVRFs  int            `json:"active_policy_vrfs"`
		TotalPolicyVLANs  int            `json:"total_policy_vlans"`
		PoliciesByNs      map[string]int `json:"policies_by_namespace"`
		RulesByNamespace  map[string]int `json:"rules_by_namespace"`
		ProtocolBreakdown map[string]int `json:"protocol_breakdown"`
	}

	policyMap := agw.PolicyHandler.ListPolicies()

	// Collect summary statistics
	summary := PolicySummary{
		RulesByNamespace:  make(map[string]int),
		PoliciesByNs:      make(map[string]int),
		ProtocolBreakdown: make(map[string]int),
	}

	// Adding resource version
	var err error
	summary.ResourceVersion, err = agw.PolicyHandler.ResourceVersion()
	if err != nil {
		summary.ResourceVersion = "failed"
	}

	vrfSet := make(map[string]bool)
	vlanSet := make(map[int32]bool)
	activeL3Networks := agw.PolicyHandler.GetL3Networks()

	for resourceID, rulesList := range policyMap {
		summary.TotalPolicies++

		// Parse resource ID (kind/namespace/name)
		parts := strings.Split(resourceID.String(), "/")
		if len(parts) >= 3 {
			namespace := parts[1]
			summary.PoliciesByNs[namespace]++
		}

		for _, rule := range rulesList {
			summary.TotalRules++

			// Count rules by namespace
			if len(parts) >= 3 {
				namespace := parts[1]
				summary.RulesByNamespace[namespace]++
			}

			if rule.SwitchPolicy == nil {
				continue
			}

			// Count allow/deny rules
			if rule.SwitchPolicy.Action.EnforceAction.Allow {
				summary.AllowRules++
			}
			if rule.SwitchPolicy.Action.EnforceAction.Deny {
				summary.DenyRules++
			}

			// Collect VRFs and check if rule is active
			srcVrf := rule.SwitchPolicy.Source.Endpoint.VRF
			dstVrf := rule.SwitchPolicy.Destination.Endpoint.VRF
			if srcVrf != "" {
				vrfSet[srcVrf] = true
			}
			if dstVrf != "" {
				vrfSet[dstVrf] = true
			}

			// A rule is active if its VRFs are in the active L3Networks
			srcActive := srcVrf == "" || activeL3Networks.HasVRF(switchpolicy.VrfName(srcVrf))
			dstActive := dstVrf == "" || activeL3Networks.HasVRF(switchpolicy.VrfName(dstVrf))
			if srcActive && dstActive {
				summary.ActiveRules++
			}

			// Collect VLANs (only positive values are active)
			if rule.SwitchPolicy.Source.Endpoint.VLAN > 0 {
				vlanSet[rule.SwitchPolicy.Source.Endpoint.VLAN] = true
			}
			if rule.SwitchPolicy.Destination.Endpoint.VLAN > 0 {
				vlanSet[rule.SwitchPolicy.Destination.Endpoint.VLAN] = true
			}

			// Collect protocol breakdown
			if rule.SwitchPolicy.Destination.ProtoPorts != nil {
				for _, pp := range *rule.SwitchPolicy.Destination.ProtoPorts {
					protoName := pp.Protocol.String()
					if protoName == "" {
						protoName = "UNSPECIFIED"
					}
					summary.ProtocolBreakdown[protoName]++
				}
			}
		}
	}

	summary.TotalPolicyVRFs = len(vrfSet)
	summary.TotalPolicyVLANs = len(vlanSet)

	// Count active policy VRFs (VRFs in policies that are also in active L3Networks)
	activeCount := 0
	for vrf := range vrfSet {
		if activeL3Networks.HasVRF(switchpolicy.VrfName(vrf)) {
			activeCount++
		}
	}
	summary.ActivePolicyVRFs = activeCount

	// If checking if the json flag was passed, format as JSON
	if msgData.Flags["json"] == "true" {
		jsonData, err := json.Marshal(summary)
		if err != nil {
			return fmt.Sprintf(`{"error": "failed to marshal summary: %v"}`, err)
		}
		return string(jsonData)
	}

	// Format as text using FormatTable
	result, err := FormatTable(summary)
	if err != nil {
		return fmt.Sprintf("Error formatting summary: %v", err)
	}
	return result
}

func (agw *AgentGateway) PoliciesTranslate(_ context.Context, msgData ipc.MessageData) (string, error) {
	filePath := msgData.Flags["file"]
	noVrfs := msgData.Flags["no-vrfs"] == "true"

	// Create a new state for translation
	// This ensures we don't affect the current state
	var nextID switchpolicy.RuleID
	state := switchpolicy.NewState(func() switchpolicy.RuleID {
		nextID++
		return nextID
	})

	var ruleID switchpolicy.RuleID = 1
	var switchPolicies []*switchpolicy.SwitchPolicy

	if filePath != "" {
		// Translate policies from file
		policies, err := switchpolicy.FromFile(filePath)
		if err != nil {
			return "", fmt.Errorf("failed to parse YAML file: %w", err)
		}
		if len(policies) == 0 {
			return "", fmt.Errorf("no policies found in file")
		}

		for _, snp := range policies {
			internalPolicies, err := switchpolicy.ToSmartSwitchNetworkPolicies(snp)
			if err != nil {
				return "", fmt.Errorf("failed to convert policy %s: %w", snp.Name, err)
			}

			for _, internalPolicy := range internalPolicies {
				switchPolicies = append(switchPolicies, &switchpolicy.SwitchPolicy{
					UID: switchpolicy.UniqueID{
						PolicyName: snp.Name,
						RuleName:   snp.Name,
					},
					Policy: internalPolicy,
				})
			}
		}
	} else {
		// Translate current policy set from the AGW
		policyMap := agw.PolicyHandler.ListPolicies()
		if len(policyMap) == 0 {
			return "", fmt.Errorf("no policies currently loaded in AGW")
		}

		for resourceID, rulesList := range policyMap {
			for _, rule := range rulesList {
				if rule.SwitchPolicy == nil {
					continue
				}
				// Deep copy the policy to avoid mutating the original when no-vrfs is set
				switchPolicies = append(switchPolicies, &switchpolicy.SwitchPolicy{
					UID: switchpolicy.UniqueID{
						PolicyName: resourceID.String(),
						RuleName:   rule.RuleName,
					},
					Policy: rule.SwitchPolicy.Copy(),
				})
			}
		}
	}

	// Set L3Networks based on no-vrfs flag
	if noVrfs {
		// When no-vrfs is set, clear all VRFs in policies so they map to the empty VRF (GID 0)
		for _, sp := range switchPolicies {
			sp.Policy.Source.Endpoint.VRF = ""
			sp.Policy.Destination.Endpoint.VRF = ""
		}
	}

	// Use the current L3Networks from the AGW
	currentL3Networks := agw.PolicyHandler.GetL3Networks()
	if _, err := state.SetL3Networks(currentL3Networks); err != nil {
		return "", fmt.Errorf("failed to set L3 networks: %w", err)
	}

	// Add all rules to state
	for _, sp := range switchPolicies {
		if err := state.AddRule(ruleID, sp); err != nil {
			return "", fmt.Errorf("failed to add rule: %w", err)
		}
		ruleID++
	}

	// Get the delta (DPU rules to apply)
	dpuRules := state.GetDeltaToApply()

	// Convert DPU rules to FwPolicyV2
	fwPolicies := policy.DPURuleToJSON(v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT, dpuRules)
	jsonBytes, err := json.Marshal(fwPolicies)
	if err != nil {
		return "", fmt.Errorf("failed to marshal policies to JSON: %w", err)
	}
	return string(jsonBytes), nil
}

func (agw *AgentGateway) Logging(_ context.Context, msgData ipc.MessageData) error {
	levelStr, ok := msgData.Flags["level"]
	if !ok || levelStr == "" {
		return fmt.Errorf("level flag is required")
	}

	// Convert string to slog.Level
	level, err := logger.ParseLevel(levelStr)
	if err != nil {
		return err
	}

	// Set the log level
	logger.SetLogLevel(level)
	logger.GetLogger().Info("Log level updated", "level", level.String())
	return nil
}

func (agw *AgentGateway) ShowDpu(_ context.Context, msgData ipc.MessageData) string {
	logger.GetLogger().Debug("Show dpu")
	statuses := agw.dpuListener.GetDisplayStatuses()

	if msgData.Flags["json"] == "true" {
		jsonData, err := json.Marshal(statuses)
		if err != nil {
			return fmt.Sprintf("Error marshaling JSON: %v", err)
		}
		return string(jsonData)
	}

	result, err := FormatTable(statuses)
	if err != nil {
		return fmt.Sprintf("Error formatting table: %v", err)
	}
	return result
}

func (agw *AgentGateway) ShowVrf(ctx context.Context) string {
	buf := new(bytes.Buffer)
	w := tabwriter.NewWriter(buf, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Global ID\tName\tGlobal\tService\tStatic\tAffinity\tPinned")

	vrfList := agw.nxosManager.VRFStore().List()

	// Sort by global ID - VRFs with GIDs first (sorted by GID), then VRFs without GIDs (sorted by name)
	sort.Slice(vrfList, func(i, j int) bool {
		hasGidI := vrfList[i].GID != 0
		hasGidJ := vrfList[j].GID != 0
		// If both have GIDs, sort by GID
		if hasGidI && hasGidJ {
			return vrfList[i].GID < vrfList[j].GID
		}
		// If only i has GID, it comes first
		if hasGidI {
			return true
		}
		// If only j has GID, it comes first
		if hasGidJ {
			return false
		}
		// Neither has GID, sort by name
		return vrfList[i].Name < vrfList[j].Name
	})

	lbModePinning := agw.nxosManager.IsLbModePinning(ctx)
	for _, v := range vrfList {
		gidStr := ""
		if v.GID != 0 {
			gidStr = fmt.Sprintf("%d", v.GID)
		}

		affinityStr := ""
		if v.Affinity >= 1 && v.Affinity != 65535 {
			affinityStr = fmt.Sprintf("%d", v.Affinity)
		}

		pinnedStr := "N/A"
		if lbModePinning {
			pinnedStr = fmt.Sprintf("%d", v.DPUPinned)
		}

		isStatic := v.Affinity >= 1 && v.Affinity != 65535
		fmt.Fprintf(w, "%s\t%s\t%t\t%t\t%t\t%s\t%s\n",
			gidStr,
			v.Name,
			v.Global,
			v.Service,
			isStatic,
			affinityStr,
			pinnedStr)
	}
	w.Flush()
	return buf.String()
}

func (agw *AgentGateway) Reopen(_ context.Context) string {
	logger.GetLogger().Debug("Reopen")
	return "Reopen ok"
}

func (agw *AgentGateway) ShowTokens(_ context.Context) string {
	logger.GetLogger().Info("Show tokens")
	if agw.Token != nil {
		at := fmt.Sprintf(
			"k8s_controller_url=%s\nk8s_service_account=%s\nk8s_namespace=%s\nk8s_token=%s",
			agw.Token.K8sControllerURL(),
			agw.Token.K8sServiceAccount(),
			agw.Token.K8sNamespace(),
			agw.Token.K8sAuthToken(),
		)
		if at != "" {
			return at
		}
	}

	return ""
}

func (agw *AgentGateway) ShowSyslog(_ context.Context) (string, error) {
	logger.GetLogger().Debug("Show syslog")

	// Pulling log config from config repository
	configObj, ok := library.GetRepository().GetConfigObject(v1alpha.ConfigType_CONFIG_TYPE_LOG_SYSLOG)
	if !ok {
		return "", errors.New("log config not found")
	}

	// Convert config object to JSON
	syslogConfig := configObj.GetConfigLogSyslog()
	if syslogConfig == nil {
		return "", errors.New("syslog config is nil")
	}
	jsonData, err := json.MarshalIndent(syslogConfig, "", "  ")
	if err != nil {
		return "", err
	}

	return string(jsonData), nil
}

func (agw *AgentGateway) LoadConfigDpu(_ context.Context, dpu string) error {
	logger.GetLogger().Debug("Load dpu", "dpu", dpu)

	// Unmarshal the JSON string into DpuConfig
	var dpuConfig v1alpha.DpuConfig
	err := json.Unmarshal([]byte(dpu), &dpuConfig)
	if err != nil {
		logger.GetLogger().Error("Failed to unmarshal dpu JSON", "error", err)
		return err
	}

	// Convert to DPU config object
	configObj := &v1alpha.ConfigObject{
		Type:   v1alpha.ConfigType_CONFIG_TYPE_DPU,
		Source: v1alpha.ConfigSource_CONFIG_SOURCE_LOCAL,
		Config: &v1alpha.ConfigObject_ConfigDpu{
			ConfigDpu: &dpuConfig,
		},
	}

	err = library.GetRepository().AddConfig(configObj)
	if err != nil {
		logger.GetLogger().Error("Failed to add dpu config", "error", err)
		return err
	}

	return nil
}

func (agw *AgentGateway) LoadSyslog(_ context.Context, syslog string) error {
	logger.GetLogger().Debug("Load syslog", "syslog", syslog)

	// Unmarshal the JSON string into LogList
	var logList LogList
	err := json.Unmarshal([]byte(syslog), &logList)
	if err != nil {
		logger.GetLogger().Error("Failed to unmarshal syslog JSON", "error", err)
		return err
	}

	// If empty list, delete config
	if len(logList) == 0 {
		err = library.GetRepository().DeleteConfig(v1alpha.ConfigType_CONFIG_TYPE_LOG_SYSLOG)
		if err != nil {
			logger.GetLogger().Error("Failed to delete syslog config", "error", err)
			return err
		}
		return nil
	}

	// Validate and apply defaults to each log configuration
	for id, logConfig := range logList {
		validatedConfig, err := validateLogConfig(id, logConfig)
		if err != nil {
			logger.GetLogger().Error("Failed to validate syslog config", "error", err)
			return err
		}
		logList[id] = validatedConfig
	}

	// Convert to syslog config object
	syslogConfig := v1alpha.LogConfigSyslog{
		Configs: make(map[string]*v1alpha.LogConfig),
	}
	for _, logConfig := range logList {
		logConfigProto := &v1alpha.LogConfig{
			Id:          logConfig.Id,
			Name:        logConfig.Name,
			Description: logConfig.Description,
			Host:        logConfig.Config.Host,
			Port:        logConfig.Config.Port,
			Protocol:    logConfig.Config.Proto,
			Tls:         logConfig.Config.Tls,
		}

		// Set authentication based on available credentials
		if logConfig.Secrets.Token != "" {
			// Use token-based authentication
			logConfigProto.Auth = &v1alpha.LogConfig_Token{
				Token: &v1alpha.Token{
					Token: logConfig.Secrets.Token,
				},
			}
		} else if logConfig.Secrets.Username != "" && logConfig.Secrets.Password != "" {
			// Use BasicAuth
			logConfigProto.Auth = &v1alpha.LogConfig_BasicAuth{
				BasicAuth: &v1alpha.BasicAuth{
					Username: logConfig.Secrets.Username,
					Password: logConfig.Secrets.Password,
				},
			}
		} else {
			// TODO: Add mTLS configuration when supported
			logger.GetLogger().Debug("mTLS authentication configuration not yet implemented", "logConfigId", logConfig.Id)
		}

		syslogConfig.Configs[logConfig.Id] = logConfigProto
	}

	// Store the validated configuration in the repository
	configObj := &v1alpha.ConfigObject{
		Type:   v1alpha.ConfigType_CONFIG_TYPE_LOG_SYSLOG,
		Config: &v1alpha.ConfigObject_ConfigLogSyslog{ConfigLogSyslog: &syslogConfig},
	}

	if err := library.GetRepository().AddConfig(configObj); err != nil {
		logger.GetLogger().Error("Failed to store syslog config", "error", err)
		return err
	}

	logger.GetLogger().Info("Successfully loaded and validated syslog configuration", "count", len(logList))
	return nil
}

func (agw *AgentGateway) ConfigAddHa(_ context.Context, msgData ipc.MessageData) string {
	filePath := msgData.Flags["file"]
	logger.GetLogger().Debug("Add HA config", "file", filePath)

	cfg, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Sprintf("Failed to read HA config file: %v", err)
	}

	var haConfig v1alpha.HaConfig
	err = json.Unmarshal(cfg, &haConfig)
	if err != nil {
		return fmt.Sprintf("Failed to unmarshal HA config: %v", err)
	}

	configObj := &v1alpha.ConfigObject{
		Type:   v1alpha.ConfigType_CONFIG_TYPE_HA,
		Source: v1alpha.ConfigSource_CONFIG_SOURCE_LOCAL,
		Config: &v1alpha.ConfigObject_ConfigHa{ConfigHa: &haConfig},
	}

	err = library.GetRepository().AddConfig(configObj)
	if err != nil {
		return fmt.Sprintf("Failed to add HA config: %v", err)
	}

	return "HA config added successfully"
}

// HaCriteriaFail sets the debug_override criterion to false, forcing ha-switchover.
func (agw *AgentGateway) HaCriteriaFail(ctx context.Context) string {
	agw.nxosManager.HAStore().UpdateLocalCriterion(ctx, nxtypes.HACritDebug, false)
	return "HA debug criterion set to fail"
}

// HaCriteriaOk sets the debug_override criterion to true, allowing normal criteria evaluation.
func (agw *AgentGateway) HaCriteriaOk(ctx context.Context) string {
	agw.nxosManager.HAStore().UpdateLocalCriterion(ctx, nxtypes.HACritDebug, true)
	return "HA debug criterion set to ok"
}

func (agw *AgentGateway) ConfigRemoveHa(_ context.Context, _ ipc.MessageData) string {
	logger.GetLogger().Debug("Remove HA config")

	err := library.GetRepository().DeleteConfig(v1alpha.ConfigType_CONFIG_TYPE_HA)
	if err != nil {
		return fmt.Sprintf("Failed to remove HA config: %v", err)
	}

	return "HA config removed successfully"
}

func (agw *AgentGateway) ConfigAddDpu(_ context.Context, msgData ipc.MessageData) string {
	filePath := msgData.Flags["file"]
	logger.GetLogger().Debug("Add DPU config", "file", filePath)

	cfg, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Sprintf("Failed to read DPU config file: %v", err)
	}

	var dpuConfig v1alpha.DpuConfig
	err = json.Unmarshal(cfg, &dpuConfig)
	if err != nil {
		return fmt.Sprintf("Failed to unmarshal DPU config: %v", err)
	}

	configObj := &v1alpha.ConfigObject{
		Type:   v1alpha.ConfigType_CONFIG_TYPE_DPU,
		Source: v1alpha.ConfigSource_CONFIG_SOURCE_LOCAL,
		Config: &v1alpha.ConfigObject_ConfigDpu{ConfigDpu: &dpuConfig},
	}

	err = library.GetRepository().AddConfig(configObj)
	if err != nil {
		return fmt.Sprintf("Failed to add DPU config: %v", err)
	}

	return "DPU config added successfully"
}

func (agw *AgentGateway) ConfigRemoveDpu(_ context.Context) string {
	logger.GetLogger().Debug("Remove DPU config")

	err := library.GetRepository().DeleteConfig(v1alpha.ConfigType_CONFIG_TYPE_DPU)
	if err != nil {
		return fmt.Sprintf("Failed to remove DPU config: %v", err)
	}

	return "DPU config removed successfully"
}

// validateLogConfig validates and applies default values to a LogConfigData
func validateLogConfig(id string, config LogConfigData) (LogConfigData, error) {
	// Apply defaults for main fields
	if config.Id == "" {
		config.Id = id // Use the map key as default ID
	}
	if config.Type == "" {
		return config, errors.New("log type is required")
	}
	if config.Type != LogTypeSyslog &&
		config.Type != LogTypeTimescape &&
		config.Type != LogTypeSplunk {
		return config, errors.New("log type is invalid")
	}

	// Check host
	ip := net.ParseIP(config.Config.Host)
	if ip == nil || ip.To4() == nil {
		return config, errors.New("invalid host: must be a valid IPv4 address")
	}

	// Check port
	port, err := strconv.Atoi(config.Config.Port)
	if err != nil {
		return config, errors.New("invalid port: must be a valid integer")
	}
	if port < 1 || port > 65535 {
		return config, errors.New("invalid port: must be between 1 and 65535")
	}

	// Check protocol
	if config.Config.Proto == "" {
		return config, errors.New("log protocol is required")
	}
	if strings.ToLower(config.Config.Proto) != "tcp" && strings.ToLower(config.Config.Proto) != "udp" {
		return config, errors.New("invalid protocol: must be 'tcp' or 'udp'")
	}

	return config, nil
}

// formatDpuRange returns a DPU range string like "1-2" or "1-4" based on count.
func formatDpuRange(dpuCount int) string {
	if dpuCount <= 1 {
		return "1"
	}
	return fmt.Sprintf("1-%d", dpuCount)
}

// GnmiShowVrf returns VRF store data.
func (agw *AgentGateway) GnmiShowVrf(_ context.Context, msgData ipc.MessageData) string {
	logger.GetLogger().Debug("Show gNMI VRF store")

	vrfs := agw.nxosManager.VRFStore().List()

	if filter := msgData.Flags["filter"]; filter != "" {
		re, err := regexp.Compile(filter)
		if err != nil {
			return fmt.Sprintf("invalid filter regex: %v", err)
		}
		filtered := vrfs[:0]
		for _, v := range vrfs {
			if re.MatchString(v.Name) {
				filtered = append(filtered, v)
			}
		}
		vrfs = filtered
	}

	// Sort: active first, then by GID ascending, then by name
	sort.Slice(vrfs, func(i, j int) bool {
		if vrfs[i].Active != vrfs[j].Active {
			return vrfs[i].Active
		}
		if vrfs[i].GID != vrfs[j].GID {
			return vrfs[i].GID < vrfs[j].GID
		}
		return vrfs[i].Name < vrfs[j].Name
	})

	if msgData.Flags["json"] == "true" {
		type VRFData struct {
			Name      string `json:"name"`
			IsGlobal  bool   `json:"is_global"`
			IsService bool   `json:"is_service"`
			IsActive  bool   `json:"is_active"`
			Affinity  uint16 `json:"affinity"`
			DPUPinned uint16 `json:"dpu_pinned"`
			GID       uint16 `json:"gid"`
			Preset    uint16 `json:"preset"`
		}
		result := struct {
			VRFs []VRFData `json:"vrfs"`
		}{}
		for _, vrf := range vrfs {
			result.VRFs = append(result.VRFs, VRFData{
				Name:      vrf.Name,
				IsGlobal:  vrf.Global,
				IsService: vrf.Service,
				IsActive:  vrf.Active,
				Affinity:  vrf.Affinity,
				DPUPinned: vrf.DPUPinned,
				GID:       vrf.GID,
				Preset:    vrf.Preset,
			})
		}
		jsonData, err := json.Marshal(result)
		if err != nil {
			return fmt.Sprintf(`{"error": "failed to marshal VRFs: %v"}`, err)
		}
		return string(jsonData)
	}

	// Text output using FormatTable
	type VRFDisplay struct {
		Name     string `json:"Name"`
		Global   bool   `json:"Global"`
		Service  bool   `json:"Service"`
		Active   bool   `json:"Active"`
		GID      string `json:"GID"`
		Preset   string `json:"Preset"`
		Affinity string `json:"Affinity"`
		Pinned   string `json:"Pinned"`
	}

	dpuCount := agw.nxosManager.DPUStore().DpuCount()
	var data []VRFDisplay
	for _, vrf := range vrfs {
		gidStr := ""
		if vrf.GID > 0 {
			gidStr = fmt.Sprintf("%d", vrf.GID)
		}
		presetStr := ""
		if vrf.Preset > 0 {
			presetStr = fmt.Sprintf("%d", vrf.Preset)
		}
		pinnedStr := ""
		if vrf.DPUPinned == 65535 {
			pinnedStr = formatDpuRange(dpuCount)
		} else if vrf.DPUPinned > 0 {
			pinnedStr = fmt.Sprintf("%d", vrf.DPUPinned)
		}
		var affinityStr string
		if vrf.Affinity == 0 {
			affinityStr = formatDpuRange(dpuCount)
		} else {
			affinityStr = fmt.Sprintf("%d", vrf.Affinity)
		}
		data = append(data, VRFDisplay{
			Name:     vrf.Name,
			Global:   vrf.Global,
			Service:  vrf.Service,
			Active:   vrf.Active,
			GID:      gidStr,
			Preset:   presetStr,
			Affinity: affinityStr,
			Pinned:   pinnedStr,
		})
	}

	result, err := FormatTable(data)
	if err != nil {
		return fmt.Sprintf("Error formatting table: %v", err)
	}
	return "=== gNMI VRF Store ===" + result
}

// GnmiShowVlan returns VLAN store data.
func (agw *AgentGateway) GnmiShowVlan(_ context.Context, msgData ipc.MessageData) string {
	logger.GetLogger().Debug("Show gNMI VLAN store")

	vlans := agw.nxosManager.VLANStore().List()

	if filter := msgData.Flags["filter"]; filter != "" {
		re, err := regexp.Compile(filter)
		if err != nil {
			return fmt.Sprintf("invalid filter regex: %v", err)
		}
		filtered := vlans[:0]
		for _, v := range vlans {
			if re.MatchString(v.Name) {
				filtered = append(filtered, v)
			}
		}
		vlans = filtered
	}

	// Sort: active first, then by name
	sort.Slice(vlans, func(i, j int) bool {
		if vlans[i].Active != vlans[j].Active {
			return vlans[i].Active
		}
		return vlans[i].Name < vlans[j].Name
	})

	if msgData.Flags["json"] == "true" {
		type VLANData struct {
			Name      string `json:"name"`
			IsGlobal  bool   `json:"is_global"`
			IsService bool   `json:"is_service"`
			IsActive  bool   `json:"is_active"`
			Affinity  uint16 `json:"affinity"`
			DPUPinned uint16 `json:"dpu_pinned"`
			ID        uint16 `json:"id"`
		}
		result := struct {
			VLANs []VLANData `json:"vlans"`
		}{}
		for _, vlan := range vlans {
			result.VLANs = append(result.VLANs, VLANData{
				Name:      vlan.Name,
				IsGlobal:  vlan.Global,
				IsService: vlan.Service,
				IsActive:  vlan.Active,
				Affinity:  vlan.Affinity,
				DPUPinned: vlan.DPUPinned,
				ID:        vlan.ID,
			})
		}
		jsonData, err := json.Marshal(result)
		if err != nil {
			return fmt.Sprintf(`{"error": "failed to marshal VLANs: %v"}`, err)
		}
		return string(jsonData)
	}

	// Text output using FormatTable
	type VLANDisplay struct {
		Name     string `json:"Name"`
		Global   bool   `json:"Global"`
		Service  bool   `json:"Service"`
		Active   bool   `json:"Active"`
		ID       string `json:"ID"`
		Affinity string `json:"Affinity"`
		Pinned   string `json:"Pinned"`
	}

	dpuCount := agw.nxosManager.DPUStore().DpuCount()
	var data []VLANDisplay
	for _, vlan := range vlans {
		idStr := ""
		if vlan.ID > 0 {
			idStr = fmt.Sprintf("%d", vlan.ID)
		}
		pinnedStr := ""
		if vlan.DPUPinned == 65535 {
			pinnedStr = formatDpuRange(dpuCount)
		} else if vlan.DPUPinned > 0 {
			pinnedStr = fmt.Sprintf("%d", vlan.DPUPinned)
		}
		var affinityStr string
		if vlan.Affinity == 0 {
			affinityStr = formatDpuRange(dpuCount)
		} else {
			affinityStr = fmt.Sprintf("%d", vlan.Affinity)
		}
		data = append(data, VLANDisplay{
			Name:     vlan.Name,
			Global:   vlan.Global,
			Service:  vlan.Service,
			Active:   vlan.Active,
			ID:       idStr,
			Affinity: affinityStr,
			Pinned:   pinnedStr,
		})
	}

	result, err := FormatTable(data)
	if err != nil {
		return fmt.Sprintf("Error formatting table: %v", err)
	}
	return "=== gNMI VLAN Store ===" + result
}

// GnmiShowDpu returns DPU store data.
func (agw *AgentGateway) GnmiShowDpu(_ context.Context, msgData ipc.MessageData) string {
	logger.GetLogger().Debug("Show gNMI DPU store")

	dpuStore := agw.nxosManager.DPUStore()
	dpus := dpuStore.List()

	// Sort DPUs by name for consistent output
	sort.Slice(dpus, func(i, j int) bool {
		return dpus[i].Name < dpus[j].Name
	})

	if filter := msgData.Flags["filter"]; filter != "" {
		re, err := regexp.Compile(filter)
		if err != nil {
			return fmt.Sprintf("invalid filter regex: %v", err)
		}
		filtered := dpus[:0]
		for _, d := range dpus {
			if re.MatchString(d.Name) {
				filtered = append(filtered, d)
			}
		}
		dpus = filtered
	}

	if msgData.Flags["json"] == "true" {
		type DPUData struct {
			Name      string `json:"name"`
			IP        string `json:"ip"`
			PortHigh  int16  `json:"port_high"`
			PortLow   int16  `json:"port_low"`
			State     string `json:"state"`
			Version   string `json:"version"`
			ModuleNum int    `json:"module_num"`
			IsOnline  bool   `json:"is_online"`
		}
		portLow, portHigh := dpuStore.GetGlobalPortRange()
		result := struct {
			DPUs              []DPUData `json:"dpus"`
			Count             int       `json:"count"`
			ExpectedCount     int       `json:"expected_count"`
			InventoryComplete bool      `json:"inventory_complete"`
			AllOnline         bool      `json:"all_online"`
			IsReady           bool      `json:"is_ready"`
			HealthyCount      int       `json:"healthy_count"`
			Healthy           bool      `json:"healthy"`
			InSync            bool      `json:"in_sync"`
			InSyncCount       int       `json:"in_sync_count"`
			GlobalPortLow     uint16    `json:"global_port_low"`
			GlobalPortHigh    uint16    `json:"global_port_high"`
			SkipDPU           bool      `json:"skip_dpu"`
		}{
			Count:             dpuStore.Count(),
			ExpectedCount:     dpuStore.DpuCount(),
			InventoryComplete: dpuStore.IsInventoryComplete(),
			AllOnline:         dpuStore.AreAllOnline(),
			IsReady:           dpuStore.IsReady(),
			HealthyCount:      dpuStore.HealthyCount(),
			Healthy:           dpuStore.IsHealthy(),
			InSync:            dpuStore.IsInSync(),
			InSyncCount:       dpuStore.InSyncCount(),
			GlobalPortLow:     portLow,
			GlobalPortHigh:    portHigh,
			SkipDPU:           dpuStore.IsSkipDPU(),
		}
		for _, dpu := range dpus {
			result.DPUs = append(result.DPUs, DPUData{
				Name:      dpu.Name,
				IP:        dpu.IP,
				PortHigh:  dpu.PortHigh,
				PortLow:   dpu.PortLow,
				State:     dpu.State.String(),
				Version:   dpu.Version,
				ModuleNum: dpu.ModuleNum,
				IsOnline:  dpu.IsOnline(),
			})
		}
		jsonData, err := json.Marshal(result)
		if err != nil {
			return fmt.Sprintf(`{"error": "failed to marshal DPUs: %v"}`, err)
		}
		return string(jsonData)
	}

	// Text output using FormatTable
	type DPUDisplay struct {
		Name     string `json:"Name"`
		IP       string `json:"IP"`
		PortHigh int16  `json:"Port High"`
		PortLow  int16  `json:"Port Low"`
		State    string `json:"State"`
		Version  string `json:"Version"`
		Module   int    `json:"Module"`
		Online   bool   `json:"Online"`
	}

	var data []DPUDisplay
	for _, dpu := range dpus {
		data = append(data, DPUDisplay{
			Name:     dpu.Name,
			IP:       dpu.IP,
			PortHigh: dpu.PortHigh,
			PortLow:  dpu.PortLow,
			State:    dpu.State.String(),
			Version:  dpu.Version,
			Module:   dpu.ModuleNum,
			Online:   dpu.IsOnline(),
		})
	}

	portLow, portHigh := dpuStore.GetGlobalPortRange()
	header := fmt.Sprintf("=== gNMI DPU Store ===\nCount: %d (Expected: %d, Healthy: %d)\nInventory Complete: %v, All Online: %v, Ready: %v\nHealthy: %v, In Sync: %v (Count: %d)\nGlobal Port Range: %d-%d, Skip DPU: %v",
		dpuStore.Count(), dpuStore.DpuCount(), dpuStore.HealthyCount(),
		dpuStore.IsInventoryComplete(), dpuStore.AreAllOnline(), dpuStore.IsReady(),
		dpuStore.IsHealthy(), dpuStore.IsInSync(), dpuStore.InSyncCount(),
		portLow, portHigh, dpuStore.IsSkipDPU())

	table, err := FormatTable(data)
	if err != nil {
		return fmt.Sprintf("Error formatting table: %v", err)
	}
	return header + table
}

// formatEpochISO returns an ISO 8601 UTC string for a unix epoch, or "" if zero.
func formatEpochISO(epoch int64) string {
	if epoch == 0 {
		return ""
	}
	return time.Unix(epoch, 0).UTC().Format(time.RFC3339)
}

// formatEpoch returns a human-readable UTC string for a unix epoch, or "N/A" if zero.
func formatEpoch(epoch int64) string {
	if epoch == 0 {
		return "N/A"
	}
	return time.Unix(epoch, 0).UTC().Format("2006-01-02 15:04:05 UTC")
}

// GnmiShowHa returns HA store data.
func (agw *AgentGateway) GnmiShowHa(_ context.Context, msgData ipc.MessageData) string {
	logger.GetLogger().Debug("Show gNMI HA store")

	haStore := agw.nxosManager.HAStore()

	local := haStore.Local()
	allPeers := haStore.AllPeers()

	if msgData.Flags["json"] == "true" {
		type LocalData struct {
			HaState          string          `json:"ha_state"`
			HaStateReason    string          `json:"ha_state_reason"`
			HaStateEpoch     string          `json:"ha_state_epoch"`
			SvcState         string          `json:"svc_state"`
			SvcStateReason   string          `json:"svc_state_reason"`
			SvcStateEpoch    string          `json:"svc_state_epoch"`
			CriteriaMet      bool            `json:"criteria_met"`
			CriteriaMetEpoch string          `json:"criteria_met_epoch"`
			PolicyCheck      bool            `json:"policy_check"`
			PolicyRev        string          `json:"policy_rev"`
			AdjacencyReached bool            `json:"adjacency_reached"`
			RecoveryPending  bool            `json:"recovery_pending"`
			RecoveryEpoch    string          `json:"recovery_epoch"`
			FlapCount        int             `json:"flap_count"`
			Criteria         map[string]bool `json:"criteria"`
		}

		localCritJSON := make(map[string]bool, len(local.Criteria))
		for k, v := range local.Criteria {
			localCritJSON[string(k)] = v
		}
		localData := LocalData{
			HaState:          local.HaState,
			HaStateReason:    local.HaStateReason.String(),
			HaStateEpoch:     formatEpochISO(local.HaStateEpoch),
			SvcState:         local.SvcState,
			SvcStateReason:   local.SvcStateReason.String(),
			SvcStateEpoch:    formatEpochISO(local.SvcStateEpoch),
			CriteriaMet:      local.CriteriaMet,
			CriteriaMetEpoch: formatEpochISO(local.CriteriaMetEpoch),
			PolicyCheck:      local.PolicyCheck,
			PolicyRev:        local.PolicyRev,
			AdjacencyReached: local.AdjacencyReached,
			RecoveryPending:  local.CriteriaRecoveryPending,
			RecoveryEpoch:    formatEpochISO(local.CriteriaRecoveryEpoch),
			FlapCount:        local.CriteriaFlapCount,
			Criteria:         localCritJSON,
		}

		peersJSON := make(map[string]bool, len(allPeers))
		for ip := range allPeers {
			peersJSON[ip] = true
		}

		result := struct {
			AdminState     string          `json:"admin_state"`
			OperState      string          `json:"oper_state"`
			IsLeader       bool            `json:"is_leader"`
			LocalIP        string          `json:"local_ip"`
			Local          LocalData       `json:"local"`
			Peers          map[string]bool `json:"peers"`
			AnyPeerAdjOk   bool            `json:"any_peer_adj_ok"`
			AnyPeerMbrFail bool            `json:"any_peer_mbr_fail"`
			AnyPeerHaReady bool            `json:"any_peer_ha_ready"`
		}{
			AdminState:     haStore.Enabled(),
			OperState:      haStore.SwitchState(),
			IsLeader:       haStore.IsLeader(),
			LocalIP:        haStore.HaIP(),
			Local:          localData,
			Peers:          peersJSON,
			AnyPeerAdjOk:   haStore.AnyPeerAdjacencyCriteriaOk(),
			AnyPeerMbrFail: haStore.AnyPeerMemberCriteriaFail(),
			AnyPeerHaReady: haStore.AnyPeerInHaReady(),
		}
		jsonData, err := json.Marshal(result)
		if err != nil {
			return fmt.Sprintf(`{"error": "failed to marshal HA: %v"}`, err)
		}
		return string(jsonData)
	}

	// Text output
	buf := new(bytes.Buffer)
	w := tabwriter.NewWriter(buf, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "=== gNMI HA Store ===")
	fmt.Fprintln(w, "\n--- Summary ---")
	fmt.Fprintf(w, "Admin State:\t%s\n", haStore.Enabled())
	fmt.Fprintf(w, "Oper State:\t%s\n", haStore.SwitchState())
	fmt.Fprintf(w, "Leader:\t%v\n", haStore.IsLeader())
	fmt.Fprintf(w, "Local IP:\t%s\n", haStore.HaIP())

	fmt.Fprintln(w, "\n--- Local State ---")
	fmt.Fprintf(w, "HA State:\t%s (%s) since %s\n", local.HaState, local.HaStateReason, formatEpoch(local.HaStateEpoch))
	fmt.Fprintf(w, "SVC State:\t%s (%s) since %s\n", local.SvcState, local.SvcStateReason, formatEpoch(local.SvcStateEpoch))
	fmt.Fprintf(w, "Criteria Met:\t%v since %s\n", local.CriteriaMet, formatEpoch(local.CriteriaMetEpoch))
	fmt.Fprintf(w, "Policy Check:\t%v\n", local.PolicyCheck)
	fmt.Fprintf(w, "Policy Rev:\t%s\n", local.PolicyRev)
	fmt.Fprintf(w, "Adjacency Reached:\t%v\n", local.AdjacencyReached)
	fmt.Fprintf(w, "Recovery Pending:\t%v\n", local.CriteriaRecoveryPending)
	fmt.Fprintf(w, "Flap Count:\t%d\n", local.CriteriaFlapCount)

	if len(local.Criteria) > 0 {
		fmt.Fprintln(w, "\nCriteria:")
		keys := make([]string, 0, len(local.Criteria))
		for k := range local.Criteria {
			keys = append(keys, string(k))
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(w, "  %s:\t%v\n", k, local.Criteria[nxtypes.HACriterion(k)])
		}
	}

	fmt.Fprintf(w, "Any Peer Adj OK:\t%v\n", haStore.AnyPeerAdjacencyCriteriaOk())
	fmt.Fprintf(w, "Any Peer Mbr Fail:\t%v\n", haStore.AnyPeerMemberCriteriaFail())
	fmt.Fprintf(w, "Any Peer HA Ready:\t%v\n", haStore.AnyPeerInHaReady())

	if len(allPeers) > 0 {
		fmt.Fprintf(w, "\nPeers: %d (use 'ha peers show' for details)\n", len(allPeers))
	}

	w.Flush()
	return buf.String()
}

// GnmiShowDevice returns device store data.
func (agw *AgentGateway) GnmiShowDevice(_ context.Context, msgData ipc.MessageData) string {
	logger.GetLogger().Debug("Show gNMI device store")

	deviceStore := agw.nxosManager.DeviceStore()

	if msgData.Flags["json"] == "true" {
		result := struct {
			SerialNumber       string `json:"serial_number"`
			Model              string `json:"model"`
			SoftwareVersion    string `json:"software_version"`
			ServiceIP          string `json:"service_ip"`
			ProxyServer        string `json:"proxy_server"`
			ProxyPort          uint32 `json:"proxy_port"`
			ProxyAddress       string `json:"proxy_address"`
			ConnectionStatus   string `json:"connection_status"`
			AdmissionStatus    string `json:"admission_status"`
			RejectReason       string `json:"reject_reason"`
			ControllerEndpoint string `json:"controller_endpoint"`
			ControllerPort     uint32 `json:"controller_port"`
			ControllerVersion  string `json:"controller_version"`
			SystemState        string `json:"system_state"`
			HeadlessMode       bool   `json:"headless_mode"`
			InService          bool   `json:"in_service"`
			InServiceState     string `json:"in_service_state"`
			SkipReg            bool   `json:"skip_reg"`
			SkipRegReason      string `json:"skip_reg_reason"`
			HasToken           bool   `json:"has_token"`
			LbMode             string `json:"lb_mode"`
		}{
			SerialNumber:       deviceStore.SerialNumber(),
			Model:              deviceStore.Model(),
			SoftwareVersion:    deviceStore.SoftwareVersion(),
			ServiceIP:          deviceStore.ServiceIP(),
			ProxyServer:        deviceStore.ProxyServer(),
			ProxyPort:          deviceStore.ProxyPort(),
			ProxyAddress:       deviceStore.ProxyAddress(),
			ConnectionStatus:   deviceStore.ConnectionStatus(),
			AdmissionStatus:    deviceStore.AdmissionStatus(),
			RejectReason:       deviceStore.RejectReason(),
			ControllerEndpoint: deviceStore.ControllerEndpoint(),
			ControllerPort:     deviceStore.ControllerPort(),
			ControllerVersion:  deviceStore.ControllerVersion(),
			SystemState:        nxos.Phase(deviceStore.SystemState()).String(),
			HeadlessMode:       deviceStore.IsHeadlessMode(),
			InService:          deviceStore.IsInService(),
			InServiceState:     deviceStore.InServiceState(),
			SkipReg:            deviceStore.SkipReg(),
			SkipRegReason:      deviceStore.SkipRegReason(),
			HasToken:           deviceStore.Token() != "",
			LbMode:             deviceStore.LbMode(),
		}
		jsonData, err := json.Marshal(result)
		if err != nil {
			return fmt.Sprintf(`{"error": "failed to marshal device: %v"}`, err)
		}
		return string(jsonData)
	}

	// Text output using FormatTable
	type DeviceDisplay struct {
		SerialNumber       string `json:"Serial Number"`
		Model              string `json:"Model"`
		SoftwareVersion    string `json:"Software Version"`
		ServiceIP          string `json:"Service IP"`
		ProxyServer        string `json:"Proxy Server"`
		ProxyPort          uint32 `json:"Proxy Port"`
		ProxyAddress       string `json:"Proxy Address"`
		ConnectionStatus   string `json:"Connection Status"`
		AdmissionStatus    string `json:"Admission Status"`
		RejectReason       string `json:"Reject Reason"`
		ControllerEndpoint string `json:"Controller Endpoint"`
		ControllerPort     uint32 `json:"Controller Port"`
		ControllerVersion  string `json:"Controller Version"`
		SystemState        string `json:"System State"`
		HeadlessMode       bool   `json:"Headless Mode"`
		InService          bool   `json:"In Service"`
		InServiceState     string `json:"In Service State"`
		SkipReg            bool   `json:"Skip Reg"`
		SkipRegReason      string `json:"Skip Reg Reason"`
		HasToken           bool   `json:"Has Token"`
		LbMode             string `json:"LB Mode"`
	}

	data := DeviceDisplay{
		SerialNumber:       deviceStore.SerialNumber(),
		Model:              deviceStore.Model(),
		SoftwareVersion:    deviceStore.SoftwareVersion(),
		ServiceIP:          deviceStore.ServiceIP(),
		ProxyServer:        deviceStore.ProxyServer(),
		ProxyPort:          deviceStore.ProxyPort(),
		ProxyAddress:       deviceStore.ProxyAddress(),
		ConnectionStatus:   deviceStore.ConnectionStatus(),
		AdmissionStatus:    deviceStore.AdmissionStatus(),
		RejectReason:       deviceStore.RejectReason(),
		ControllerEndpoint: deviceStore.ControllerEndpoint(),
		ControllerPort:     deviceStore.ControllerPort(),
		ControllerVersion:  deviceStore.ControllerVersion(),
		SystemState:        nxos.Phase(deviceStore.SystemState()).String(),
		HeadlessMode:       deviceStore.IsHeadlessMode(),
		InService:          deviceStore.IsInService(),
		InServiceState:     deviceStore.InServiceState(),
		SkipReg:            deviceStore.SkipReg(),
		SkipRegReason:      deviceStore.SkipRegReason(),
		HasToken:           deviceStore.Token() != "",
		LbMode:             deviceStore.LbMode(),
	}

	table, err := FormatTable(data)
	if err != nil {
		return fmt.Sprintf("Error formatting table: %v", err)
	}
	return "=== gNMI Device Store ===\n" + table
}

// GnmiShowVrfList returns a compact table of active VRFs with a count summary.
func (agw *AgentGateway) GnmiShowVrfList(_ context.Context, msgData ipc.MessageData) string {
	logger.GetLogger().Debug("Show gNMI VRF list (active only)")

	allVRFs := agw.nxosManager.VRFStore().List()
	active := agw.nxosManager.VRFStore().ListActive()

	sort.Slice(active, func(i, j int) bool {
		if active[i].GID != active[j].GID {
			return active[i].GID < active[j].GID
		}
		return active[i].Name < active[j].Name
	})

	if msgData.Flags["json"] == "true" {
		type VRFEntry struct {
			Name     string `json:"name"`
			GID      uint16 `json:"gid"`
			Affinity uint16 `json:"affinity"`
			Pinned   uint16 `json:"dpu_pinned"`
		}
		result := struct {
			ActiveCount int        `json:"active_count"`
			TotalCount  int        `json:"total_count"`
			VRFs        []VRFEntry `json:"vrfs"`
		}{
			ActiveCount: len(active),
			TotalCount:  len(allVRFs),
		}
		for _, v := range active {
			result.VRFs = append(result.VRFs, VRFEntry{
				Name:     v.Name,
				GID:      v.GID,
				Affinity: v.Affinity,
				Pinned:   v.DPUPinned,
			})
		}
		jsonData, err := json.Marshal(result)
		if err != nil {
			return fmt.Sprintf(`{"error": "failed to marshal VRF list: %v"}`, err)
		}
		return string(jsonData)
	}

	type VRFListDisplay struct {
		Name     string `json:"Name"`
		GID      string `json:"GID"`
		Affinity string `json:"Affinity"`
		Pinned   string `json:"Pinned"`
	}
	dpuCount := agw.nxosManager.DPUStore().DpuCount()
	var data []VRFListDisplay
	for _, v := range active {
		gidStr := ""
		if v.GID > 0 {
			gidStr = fmt.Sprintf("%d", v.GID)
		}
		pinnedStr := ""
		if v.DPUPinned == 65535 {
			pinnedStr = formatDpuRange(dpuCount)
		} else if v.DPUPinned > 0 {
			pinnedStr = fmt.Sprintf("%d", v.DPUPinned)
		}
		var affinityStr string
		if v.Affinity == 0 {
			affinityStr = formatDpuRange(dpuCount)
		} else {
			affinityStr = fmt.Sprintf("%d", v.Affinity)
		}
		data = append(data, VRFListDisplay{Name: v.Name, GID: gidStr, Affinity: affinityStr, Pinned: pinnedStr})
	}
	table, err := FormatTable(data)
	if err != nil {
		return fmt.Sprintf("Error formatting table: %v", err)
	}
	return fmt.Sprintf("=== Active VRFs (%d of %d) ===", len(active), len(allVRFs)) + table
}

// GnmiShowVrfInfo returns aggregate VRF statistics.
func (agw *AgentGateway) GnmiShowVrfInfo(_ context.Context, msgData ipc.MessageData) string {
	logger.GetLogger().Debug("Show gNMI VRF info")

	vrfs := agw.nxosManager.VRFStore().List()

	var total, active, globalOnly, serviceOnly, gidsAllocated, staticPinning, dynamicPinning, unpinned int
	total = len(vrfs)
	for _, v := range vrfs {
		isActive := v.Active
		if isActive {
			active++
		} else if v.Global {
			globalOnly++
		} else if v.Service {
			serviceOnly++
		}
		if v.GID > 0 {
			gidsAllocated++
		}
		if v.DPUPinned > 0 {
			if v.Affinity > 0 {
				staticPinning++
			} else {
				dynamicPinning++
			}
		} else {
			unpinned++
		}
	}

	if msgData.Flags["json"] == "true" {
		result := struct {
			Total          int `json:"total"`
			Active         int `json:"active"`
			GlobalOnly     int `json:"global_only"`
			ServiceOnly    int `json:"service_only"`
			GIDsAllocated  int `json:"gids_allocated"`
			StaticPinning  int `json:"static_pinning"`
			DynamicPinning int `json:"dynamic_pinning"`
			Unpinned       int `json:"unpinned"`
		}{
			Total:          total,
			Active:         active,
			GlobalOnly:     globalOnly,
			ServiceOnly:    serviceOnly,
			GIDsAllocated:  gidsAllocated,
			StaticPinning:  staticPinning,
			DynamicPinning: dynamicPinning,
			Unpinned:       unpinned,
		}
		jsonData, err := json.Marshal(result)
		if err != nil {
			return fmt.Sprintf(`{"error": "failed to marshal VRF info: %v"}`, err)
		}
		return string(jsonData)
	}

	buf := new(bytes.Buffer)
	w := tabwriter.NewWriter(buf, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "=== VRF Info ===")
	fmt.Fprintf(w, "  Total:\t%d\n", total)
	fmt.Fprintf(w, "  Active:\t%d  (global + service)\n", active)
	fmt.Fprintf(w, "  Global Only:\t%d\n", globalOnly)
	fmt.Fprintf(w, "  Service Only:\t%d\n", serviceOnly)
	fmt.Fprintf(w, "  GIDs Allocated:\t%d\n", gidsAllocated)
	fmt.Fprintf(w, "  Static Pinning:\t%d\n", staticPinning)
	fmt.Fprintf(w, "  Dynamic Pinning:\t%d\n", dynamicPinning)
	fmt.Fprintf(w, "  Unpinned:\t%d\n", unpinned)
	w.Flush()
	return buf.String()
}

// GnmiShowVrfGids returns the GID allocation table for VRFs.
func (agw *AgentGateway) GnmiShowVrfGids(_ context.Context, msgData ipc.MessageData) string {
	logger.GetLogger().Debug("Show gNMI VRF GIDs")

	allVRFs := agw.nxosManager.VRFStore().List()
	nextGID := agw.nxosManager.VRFStore().NextGID()

	// Filter to VRFs with GID > 0 or Preset > 0
	var gidVRFs []nxtypes.VRF
	for _, v := range allVRFs {
		if v.GID > 0 || v.Preset > 0 {
			gidVRFs = append(gidVRFs, v)
		}
	}
	// Sort: active first, then by GID ascending, then by name
	sort.Slice(gidVRFs, func(i, j int) bool {
		if gidVRFs[i].Active != gidVRFs[j].Active {
			return gidVRFs[i].Active
		}
		if gidVRFs[i].GID != gidVRFs[j].GID {
			return gidVRFs[i].GID < gidVRFs[j].GID
		}
		return gidVRFs[i].Name < gidVRFs[j].Name
	})

	if msgData.Flags["json"] == "true" {
		type GIDEntry struct {
			Name   string `json:"name"`
			GID    uint16 `json:"gid"`
			Preset uint16 `json:"preset"`
			Active bool   `json:"active"`
		}
		result := struct {
			Count   int        `json:"count"`
			NextGID uint16     `json:"next_gid"`
			GIDs    []GIDEntry `json:"gids"`
		}{
			Count:   len(gidVRFs),
			NextGID: nextGID,
		}
		for _, v := range gidVRFs {
			result.GIDs = append(result.GIDs, GIDEntry{
				Name:   v.Name,
				GID:    v.GID,
				Preset: v.Preset,
				Active: v.Active,
			})
		}
		jsonData, err := json.Marshal(result)
		if err != nil {
			return fmt.Sprintf(`{"error": "failed to marshal VRF GIDs: %v"}`, err)
		}
		return string(jsonData)
	}

	type GIDDisplay struct {
		VRFName string `json:"VRF Name"`
		GID     string `json:"GID"`
		Preset  string `json:"Preset"`
		Active  bool   `json:"Active"`
	}
	var data []GIDDisplay
	for _, v := range gidVRFs {
		gidStr := ""
		if v.GID > 0 {
			gidStr = fmt.Sprintf("%d", v.GID)
		}
		presetStr := ""
		if v.Preset > 0 {
			presetStr = fmt.Sprintf("%d", v.Preset)
		}
		data = append(data, GIDDisplay{
			VRFName: v.Name,
			GID:     gidStr,
			Preset:  presetStr,
			Active:  v.Active,
		})
	}
	table, err := FormatTable(data)
	if err != nil {
		return fmt.Sprintf("Error formatting table: %v", err)
	}
	return fmt.Sprintf("=== VRF GID Allocations (%d in use, next=%d) ===", len(gidVRFs), nextGID) + table
}

// GnmiShowVrfPeers returns per-peer VRF GID reconciliation state.
func (agw *AgentGateway) GnmiShowVrfPeers(_ context.Context, msgData ipc.MessageData) string {
	logger.GetLogger().Debug("Show gNMI VRF peers")

	haStore := agw.nxosManager.HAStore()
	allPeers := haStore.AllPeers()

	// Sort peers by IP for consistent output
	ips := make([]string, 0, len(allPeers))
	for ip := range allPeers {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	if msgData.Flags["json"] == "true" {
		type PeerEntry struct {
			IP                   string `json:"ip"`
			AdjacencyCriteriaMet bool   `json:"adjacency_criteria_met"`
			PeerVrfGid           bool   `json:"peer_vrf_gid"`
		}
		result := struct {
			Count int         `json:"count"`
			Peers []PeerEntry `json:"peers"`
		}{
			Count: len(allPeers),
		}
		for _, ip := range ips {
			peer := allPeers[ip]
			vrfGid := peer.AdjacencyCriteria[nxtypes.HACritPeerVrfGid]
			result.Peers = append(result.Peers, PeerEntry{
				IP:                   ip,
				AdjacencyCriteriaMet: peer.AdjacencyCriteriaMet,
				PeerVrfGid:           vrfGid,
			})
		}
		jsonData, err := json.Marshal(result)
		if err != nil {
			return fmt.Sprintf(`{"error": "failed to marshal VRF peers: %v"}`, err)
		}
		return string(jsonData)
	}

	buf := new(bytes.Buffer)
	w := tabwriter.NewWriter(buf, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "=== VRF Peer Reconciliation ===")
	fmt.Fprintf(w, "Peers: %d\n", len(allPeers))
	if len(allPeers) > 0 {
		fmt.Fprintln(w, "")
		fmt.Fprintf(w, "%-20s\t%-20s\t%-12s\n", "Peer IP", "Adj Criteria Met", "VRF GID OK")
		for _, ip := range ips {
			peer := allPeers[ip]
			vrfGid := peer.AdjacencyCriteria[nxtypes.HACritPeerVrfGid]
			fmt.Fprintf(w, "%-20s\t%-20v\t%-12v\n", ip, peer.AdjacencyCriteriaMet, vrfGid)
		}
	}
	w.Flush()
	return buf.String()
}

// GnmiShowVlanList returns a compact table of active VLANs with a count summary.
func (agw *AgentGateway) GnmiShowVlanList(_ context.Context, msgData ipc.MessageData) string {
	logger.GetLogger().Debug("Show gNMI VLAN list (active only)")

	allVLANs := agw.nxosManager.VLANStore().List()
	active := agw.nxosManager.VLANStore().ListActive()

	sort.Slice(active, func(i, j int) bool {
		return active[i].Name < active[j].Name
	})

	if msgData.Flags["json"] == "true" {
		type VLANEntry struct {
			Name     string `json:"name"`
			ID       uint16 `json:"id"`
			Affinity uint16 `json:"affinity"`
			Pinned   uint16 `json:"dpu_pinned"`
		}
		result := struct {
			ActiveCount int         `json:"active_count"`
			TotalCount  int         `json:"total_count"`
			VLANs       []VLANEntry `json:"vlans"`
		}{
			ActiveCount: len(active),
			TotalCount:  len(allVLANs),
		}
		for _, v := range active {
			result.VLANs = append(result.VLANs, VLANEntry{
				Name:     v.Name,
				ID:       v.ID,
				Affinity: v.Affinity,
				Pinned:   v.DPUPinned,
			})
		}
		jsonData, err := json.Marshal(result)
		if err != nil {
			return fmt.Sprintf(`{"error": "failed to marshal VLAN list: %v"}`, err)
		}
		return string(jsonData)
	}

	type VLANListDisplay struct {
		Name     string `json:"Name"`
		ID       string `json:"ID"`
		Affinity string `json:"Affinity"`
		Pinned   string `json:"Pinned"`
	}
	dpuCount := agw.nxosManager.DPUStore().DpuCount()
	var data []VLANListDisplay
	for _, v := range active {
		idStr := ""
		if v.ID > 0 {
			idStr = fmt.Sprintf("%d", v.ID)
		}
		pinnedStr := ""
		if v.DPUPinned == 65535 {
			pinnedStr = formatDpuRange(dpuCount)
		} else if v.DPUPinned > 0 {
			pinnedStr = fmt.Sprintf("%d", v.DPUPinned)
		}
		var affinityStr string
		if v.Affinity == 0 {
			affinityStr = formatDpuRange(dpuCount)
		} else {
			affinityStr = fmt.Sprintf("%d", v.Affinity)
		}
		data = append(data, VLANListDisplay{Name: v.Name, ID: idStr, Affinity: affinityStr, Pinned: pinnedStr})
	}
	table, err := FormatTable(data)
	if err != nil {
		return fmt.Sprintf("Error formatting table: %v", err)
	}
	return fmt.Sprintf("=== Active VLANs (%d of %d) ===", len(active), len(allVLANs)) + table
}

// GnmiShowVlanInfo returns aggregate VLAN statistics.
func (agw *AgentGateway) GnmiShowVlanInfo(_ context.Context, msgData ipc.MessageData) string {
	logger.GetLogger().Debug("Show gNMI VLAN info")

	vlans := agw.nxosManager.VLANStore().List()

	var total, active, globalOnly, serviceOnly, staticPinning, dynamicPinning, unpinned, idsAssigned int
	total = len(vlans)
	for _, v := range vlans {
		isActive := v.Active
		if isActive {
			active++
		} else if v.Global {
			globalOnly++
		} else if v.Service {
			serviceOnly++
		}
		if v.ID > 0 {
			idsAssigned++
		}
		if v.DPUPinned > 0 {
			if v.Affinity > 0 {
				staticPinning++
			} else {
				dynamicPinning++
			}
		} else {
			unpinned++
		}
	}

	if msgData.Flags["json"] == "true" {
		result := struct {
			Total          int `json:"total"`
			Active         int `json:"active"`
			GlobalOnly     int `json:"global_only"`
			ServiceOnly    int `json:"service_only"`
			IDsAssigned    int `json:"ids_assigned"`
			StaticPinning  int `json:"static_pinning"`
			DynamicPinning int `json:"dynamic_pinning"`
			Unpinned       int `json:"unpinned"`
		}{
			Total:          total,
			Active:         active,
			GlobalOnly:     globalOnly,
			ServiceOnly:    serviceOnly,
			IDsAssigned:    idsAssigned,
			StaticPinning:  staticPinning,
			DynamicPinning: dynamicPinning,
			Unpinned:       unpinned,
		}
		jsonData, err := json.Marshal(result)
		if err != nil {
			return fmt.Sprintf(`{"error": "failed to marshal VLAN info: %v"}`, err)
		}
		return string(jsonData)
	}

	buf := new(bytes.Buffer)
	w := tabwriter.NewWriter(buf, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "=== VLAN Info ===")
	fmt.Fprintf(w, "  Total:\t%d\n", total)
	fmt.Fprintf(w, "  Active:\t%d  (global + service)\n", active)
	fmt.Fprintf(w, "  Global Only:\t%d\n", globalOnly)
	fmt.Fprintf(w, "  Service Only:\t%d\n", serviceOnly)
	fmt.Fprintf(w, "  IDs Assigned:\t%d\n", idsAssigned)
	fmt.Fprintf(w, "  Static Pinning:\t%d\n", staticPinning)
	fmt.Fprintf(w, "  Dynamic Pinning:\t%d\n", dynamicPinning)
	fmt.Fprintf(w, "  Unpinned:\t%d\n", unpinned)
	w.Flush()
	return buf.String()
}

// GnmiShowDpuStatus returns DPU fleet status summary without per-DPU table.
func (agw *AgentGateway) GnmiShowDpuStatus(_ context.Context, msgData ipc.MessageData) string {
	logger.GetLogger().Debug("Show gNMI DPU status")

	dpuStore := agw.nxosManager.DPUStore()
	portLow, portHigh := dpuStore.GetGlobalPortRange()

	if msgData.Flags["json"] == "true" {
		result := struct {
			Count             int    `json:"count"`
			ExpectedCount     int    `json:"expected_count"`
			InventoryComplete bool   `json:"inventory_complete"`
			AllOnline         bool   `json:"all_online"`
			IsReady           bool   `json:"is_ready"`
			HealthyCount      int    `json:"healthy_count"`
			Healthy           bool   `json:"healthy"`
			InSync            bool   `json:"in_sync"`
			InSyncCount       int    `json:"in_sync_count"`
			GlobalPortLow     uint16 `json:"global_port_low"`
			GlobalPortHigh    uint16 `json:"global_port_high"`
			SkipDPU           bool   `json:"skip_dpu"`
		}{
			Count:             dpuStore.Count(),
			ExpectedCount:     dpuStore.DpuCount(),
			InventoryComplete: dpuStore.IsInventoryComplete(),
			AllOnline:         dpuStore.AreAllOnline(),
			IsReady:           dpuStore.IsReady(),
			HealthyCount:      dpuStore.HealthyCount(),
			Healthy:           dpuStore.IsHealthy(),
			InSync:            dpuStore.IsInSync(),
			InSyncCount:       dpuStore.InSyncCount(),
			GlobalPortLow:     portLow,
			GlobalPortHigh:    portHigh,
			SkipDPU:           dpuStore.IsSkipDPU(),
		}
		jsonData, err := json.Marshal(result)
		if err != nil {
			return fmt.Sprintf(`{"error": "failed to marshal DPU status: %v"}`, err)
		}
		return string(jsonData)
	}

	buf := new(bytes.Buffer)
	w := tabwriter.NewWriter(buf, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "=== DPU Fleet Status ===")
	fmt.Fprintf(w, "  Count:\t%d (Expected: %d)\n", dpuStore.Count(), dpuStore.DpuCount())
	fmt.Fprintf(w, "  Healthy:\t%v (%d healthy)\n", dpuStore.IsHealthy(), dpuStore.HealthyCount())
	fmt.Fprintf(w, "  Inventory Complete:\t%v\n", dpuStore.IsInventoryComplete())
	fmt.Fprintf(w, "  All Online:\t%v\n", dpuStore.AreAllOnline())
	fmt.Fprintf(w, "  Ready:\t%v\n", dpuStore.IsReady())
	fmt.Fprintf(w, "  In Sync:\t%v (%d in sync)\n", dpuStore.IsInSync(), dpuStore.InSyncCount())
	fmt.Fprintf(w, "  Global Port Range:\t%d-%d\n", portLow, portHigh)
	fmt.Fprintf(w, "  Skip DPU:\t%v\n", dpuStore.IsSkipDPU())
	w.Flush()
	return buf.String()
}

// GnmiShowHaPeers returns per-peer HA state details with optional IP filter.
func (agw *AgentGateway) GnmiShowHaPeers(_ context.Context, msgData ipc.MessageData) string {
	logger.GetLogger().Debug("Show gNMI HA peers")

	haStore := agw.nxosManager.HAStore()
	allPeers := haStore.AllPeers()

	// Sort peer IPs for deterministic output
	peerIPs := make([]string, 0, len(allPeers))
	for ip := range allPeers {
		peerIPs = append(peerIPs, ip)
	}
	sort.Strings(peerIPs)

	// Apply filter
	if filter := msgData.Flags["filter"]; filter != "" {
		re, err := regexp.Compile(filter)
		if err != nil {
			return fmt.Sprintf("invalid filter regex: %v", err)
		}
		filtered := peerIPs[:0]
		for _, ip := range peerIPs {
			if re.MatchString(ip) {
				filtered = append(filtered, ip)
			}
		}
		peerIPs = filtered
	}

	if msgData.Flags["json"] == "true" {
		type DPUVersionData struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		type MemberInfoData struct {
			SerialNum    string           `json:"serial_num"`
			Model        string           `json:"model"`
			SWVersion    string           `json:"sw_version"`
			AgentVersion string           `json:"agent_version"`
			HaState      string           `json:"ha_state"`
			Service      string           `json:"service"`
			LbMode       string           `json:"lb_mode"`
			PolicyCheck  bool             `json:"policy_check"`
			DPUs         []DPUVersionData `json:"dpus"`
		}
		type DPUHAStatusData struct {
			KeepaliveUp   bool `json:"keepalive_up"`
			BulkSyncLocal bool `json:"bulk_sync_local"`
			BulkSyncPeer  bool `json:"bulk_sync_peer"`
		}
		type PeerData struct {
			SvcState                  string                     `json:"svc_state"`
			SvcStateReason            string                     `json:"svc_state_reason"`
			SvcStateEpoch             string                     `json:"svc_state_epoch"`
			AdjacencyConnected        bool                       `json:"adjacency_connected"`
			AdjacencyConnectedEpoch   string                     `json:"adjacency_connected_epoch"`
			MemberCriteria            map[string]bool            `json:"member_criteria"`
			MemberCriteriaMet         bool                       `json:"member_criteria_met"`
			MemberCriteriaMetEpoch    string                     `json:"member_criteria_met_epoch"`
			AdjacencyCriteria         map[string]bool            `json:"adjacency_criteria"`
			AdjacencyCriteriaMet      bool                       `json:"adjacency_criteria_met"`
			AdjacencyCriteriaMetEpoch string                     `json:"adjacency_criteria_met_epoch"`
			DPUHAStatuses             map[string]DPUHAStatusData `json:"dpu_ha_statuses,omitempty"`
			MemberInfo                *MemberInfoData            `json:"member_info,omitempty"`
		}
		peersData := make(map[string]PeerData, len(peerIPs))
		for _, ip := range peerIPs {
			peer := allPeers[ip]
			mbrCrit := make(map[string]bool, len(peer.MemberCriteria))
			for k, v := range peer.MemberCriteria {
				mbrCrit[string(k)] = v
			}
			adjCrit := make(map[string]bool, len(peer.AdjacencyCriteria))
			for k, v := range peer.AdjacencyCriteria {
				adjCrit[string(k)] = v
			}
			var dpuHAStatuses map[string]DPUHAStatusData
			if len(peer.DPUStatuses) > 0 {
				dpuHAStatuses = make(map[string]DPUHAStatusData, len(peer.DPUStatuses))
				for uid, s := range peer.DPUStatuses {
					dpuHAStatuses[uid] = DPUHAStatusData{
						KeepaliveUp:   s.KeepaliveUp,
						BulkSyncLocal: s.BulkSyncLocal,
						BulkSyncPeer:  s.BulkSyncPeer,
					}
				}
			}
			pd := PeerData{
				SvcState:                  peer.SvcState,
				SvcStateReason:            peer.SvcStateReason.String(),
				SvcStateEpoch:             formatEpochISO(peer.SvcStateEpoch),
				AdjacencyConnected:        peer.AdjacencyConnected,
				AdjacencyConnectedEpoch:   formatEpochISO(peer.AdjacencyConnectedEpoch),
				MemberCriteria:            mbrCrit,
				MemberCriteriaMet:         peer.MemberCriteriaMet,
				MemberCriteriaMetEpoch:    formatEpochISO(peer.MemberCriteriaMetEpoch),
				AdjacencyCriteria:         adjCrit,
				AdjacencyCriteriaMet:      peer.AdjacencyCriteriaMet,
				AdjacencyCriteriaMetEpoch: formatEpochISO(peer.AdjacencyCriteriaMetEpoch),
				DPUHAStatuses:             dpuHAStatuses,
			}
			if peer.MemberInfo != nil {
				dpus := make([]DPUVersionData, len(peer.MemberInfo.DPUs))
				for i, d := range peer.MemberInfo.DPUs {
					dpus[i] = DPUVersionData{Name: d.Name, Version: d.Version}
				}
				pd.MemberInfo = &MemberInfoData{
					SerialNum:    peer.MemberInfo.SerialNum,
					Model:        peer.MemberInfo.Model,
					SWVersion:    peer.MemberInfo.SWVersion,
					AgentVersion: peer.MemberInfo.CPAVersion,
					HaState:      peer.MemberInfo.HaState,
					Service:      peer.MemberInfo.Service,
					LbMode:       peer.MemberInfo.LbMode,
					PolicyCheck:  peer.MemberInfo.PolicyCheck,
					DPUs:         dpus,
				}
			}
			peersData[ip] = pd
		}
		result := struct {
			PeerCount int                 `json:"peer_count"`
			Peers     map[string]PeerData `json:"peers"`
		}{
			PeerCount: len(peerIPs),
			Peers:     peersData,
		}
		jsonData, err := json.Marshal(result)
		if err != nil {
			return fmt.Sprintf(`{"error": "failed to marshal HA peers: %v"}`, err)
		}
		return string(jsonData)
	}

	if len(peerIPs) == 0 {
		return "=== HA Peers ===\n  (no peers)\n"
	}

	buf := new(bytes.Buffer)
	w := tabwriter.NewWriter(buf, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "=== HA Peers ===")
	for _, ip := range peerIPs {
		peer := allPeers[ip]
		fmt.Fprintf(w, "\n--- Peer: %s ---\n", ip)
		fmt.Fprintf(w, "Svc State:\t%s (%s) since %s\n", peer.SvcState, peer.SvcStateReason, formatEpoch(peer.SvcStateEpoch))
		fmt.Fprintf(w, "Adjacency Connected:\t%v since %s\n", peer.AdjacencyConnected, formatEpoch(peer.AdjacencyConnectedEpoch))

		fmt.Fprintf(w, "\nMember Criteria Met:\t%v since %s\n", peer.MemberCriteriaMet, formatEpoch(peer.MemberCriteriaMetEpoch))
		mbrKeys := make([]string, 0, len(peer.MemberCriteria))
		for k := range peer.MemberCriteria {
			mbrKeys = append(mbrKeys, string(k))
		}
		sort.Strings(mbrKeys)
		for _, k := range mbrKeys {
			fmt.Fprintf(w, "  %s:\t%v\n", k, peer.MemberCriteria[nxtypes.HACriterion(k)])
		}

		fmt.Fprintf(w, "\nAdjacency Criteria Met:\t%v since %s\n", peer.AdjacencyCriteriaMet, formatEpoch(peer.AdjacencyCriteriaMetEpoch))
		adjKeys := make([]string, 0, len(peer.AdjacencyCriteria))
		for k := range peer.AdjacencyCriteria {
			adjKeys = append(adjKeys, string(k))
		}
		sort.Strings(adjKeys)
		for _, k := range adjKeys {
			fmt.Fprintf(w, "  %s:\t%v\n", k, peer.AdjacencyCriteria[nxtypes.HACriterion(k)])
		}

		if peer.MemberInfo != nil {
			fmt.Fprintln(w, "\nMember Info:")
			fmt.Fprintf(w, "  Serial:\t%s\n", peer.MemberInfo.SerialNum)
			fmt.Fprintf(w, "  Model:\t%s\n", peer.MemberInfo.Model)
			fmt.Fprintf(w, "  SW Version:\t%s\n", peer.MemberInfo.SWVersion)
			fmt.Fprintf(w, "  CPA Version:\t%s\n", peer.MemberInfo.CPAVersion)
			fmt.Fprintf(w, "  HA State:\t%s\n", peer.MemberInfo.HaState)
			fmt.Fprintf(w, "  Service:\t%s\n", peer.MemberInfo.Service)
			fmt.Fprintf(w, "  LB Mode:\t%s\n", peer.MemberInfo.LbMode)
			fmt.Fprintf(w, "  Policy Rev:\t%s\n", peer.MemberInfo.PolicyRev)
			fmt.Fprintf(w, "  Policy Check:\t%v\n", peer.MemberInfo.PolicyCheck)
			if len(peer.MemberInfo.DPUs) > 0 {
				dpuParts := make([]string, len(peer.MemberInfo.DPUs))
				for i, d := range peer.MemberInfo.DPUs {
					dpuParts[i] = d.Name + "(" + d.Version + ")"
				}
				fmt.Fprintf(w, "  DPUs:\t%s\n", strings.Join(dpuParts, ", "))
			}
		}

		if len(peer.DPUStatuses) > 0 {
			fmt.Fprintln(w, "\nDPU HA Status:")
			dpuUIDs := make([]string, 0, len(peer.DPUStatuses))
			for uid := range peer.DPUStatuses {
				dpuUIDs = append(dpuUIDs, uid)
			}
			sort.Strings(dpuUIDs)
			for _, uid := range dpuUIDs {
				s := peer.DPUStatuses[uid]
				keepalive := "down"
				if s.KeepaliveUp {
					keepalive = "up"
				}
				bulkLocal := "pending"
				if s.BulkSyncLocal {
					bulkLocal = "done"
				}
				bulkPeer := "pending"
				if s.BulkSyncPeer {
					bulkPeer = "done"
				}
				fmt.Fprintf(w, "  %s:\tkeepalive=%-4s  bulk_sync_local=%-7s  bulk_sync_peer=%s\n",
					uid, keepalive, bulkLocal, bulkPeer)
			}
		}
	}
	w.Flush()
	return buf.String()
}

// GnmiShowHaCriteria returns all local and peer HA criteria in a compact view.
func (agw *AgentGateway) GnmiShowHaCriteria(_ context.Context, msgData ipc.MessageData) string {
	logger.GetLogger().Debug("Show gNMI HA criteria")

	haStore := agw.nxosManager.HAStore()
	local := haStore.Local()
	allPeers := haStore.AllPeers()

	// Sort peer IPs for deterministic output
	peerIPs := make([]string, 0, len(allPeers))
	for ip := range allPeers {
		peerIPs = append(peerIPs, ip)
	}
	sort.Strings(peerIPs)

	if msgData.Flags["json"] == "true" {
		localCrit := make(map[string]bool, len(local.Criteria))
		for k, v := range local.Criteria {
			localCrit[string(k)] = v
		}
		type PeerCriteriaData struct {
			MemberCriteria    map[string]bool `json:"member_criteria"`
			MemberMet         bool            `json:"member_met"`
			AdjacencyCriteria map[string]bool `json:"adjacency_criteria"`
			AdjacencyMet      bool            `json:"adjacency_met"`
		}
		peersData := make(map[string]PeerCriteriaData, len(peerIPs))
		for _, ip := range peerIPs {
			peer := allPeers[ip]
			mbrCrit := make(map[string]bool, len(peer.MemberCriteria))
			for k, v := range peer.MemberCriteria {
				mbrCrit[string(k)] = v
			}
			adjCrit := make(map[string]bool, len(peer.AdjacencyCriteria))
			for k, v := range peer.AdjacencyCriteria {
				adjCrit[string(k)] = v
			}
			peersData[ip] = PeerCriteriaData{
				MemberCriteria:    mbrCrit,
				MemberMet:         peer.MemberCriteriaMet,
				AdjacencyCriteria: adjCrit,
				AdjacencyMet:      peer.AdjacencyCriteriaMet,
			}
		}
		result := struct {
			LocalCriteria map[string]bool             `json:"local_criteria"`
			LocalMet      bool                        `json:"local_met"`
			Peers         map[string]PeerCriteriaData `json:"peers"`
		}{
			LocalCriteria: localCrit,
			LocalMet:      local.CriteriaMet,
			Peers:         peersData,
		}
		jsonData, err := json.Marshal(result)
		if err != nil {
			return fmt.Sprintf(`{"error": "failed to marshal HA criteria: %v"}`, err)
		}
		return string(jsonData)
	}

	buf := new(bytes.Buffer)
	w := tabwriter.NewWriter(buf, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "=== HA Criteria ===")
	fmt.Fprintf(w, "\n--- Local (met: %v) ---\n", local.CriteriaMet)
	if len(local.Criteria) > 0 {
		keys := make([]string, 0, len(local.Criteria))
		for k := range local.Criteria {
			keys = append(keys, string(k))
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(w, "  %s:\t%v\n", k, local.Criteria[nxtypes.HACriterion(k)])
		}
	} else {
		fmt.Fprintln(w, "  (none)")
	}

	for _, ip := range peerIPs {
		peer := allPeers[ip]
		fmt.Fprintf(w, "\n--- Peer %s ---\n", ip)

		fmt.Fprintf(w, "  Member (met: %v):\n", peer.MemberCriteriaMet)
		mbrKeys := make([]string, 0, len(peer.MemberCriteria))
		for k := range peer.MemberCriteria {
			mbrKeys = append(mbrKeys, string(k))
		}
		sort.Strings(mbrKeys)
		for _, k := range mbrKeys {
			fmt.Fprintf(w, "    %s:\t%v\n", k, peer.MemberCriteria[nxtypes.HACriterion(k)])
		}

		fmt.Fprintf(w, "  Adjacency (met: %v):\n", peer.AdjacencyCriteriaMet)
		adjKeys := make([]string, 0, len(peer.AdjacencyCriteria))
		for k := range peer.AdjacencyCriteria {
			adjKeys = append(adjKeys, string(k))
		}
		sort.Strings(adjKeys)
		for _, k := range adjKeys {
			fmt.Fprintf(w, "    %s:\t%v\n", k, peer.AdjacencyCriteria[nxtypes.HACriterion(k)])
		}
	}

	w.Flush()
	return buf.String()
}

// mockGnmiHandler returns the mock handler if active, or nil otherwise.
func (agw *AgentGateway) mockGnmiHandler() *mock.Handler {
	h, ok := agw.nxosManager.GnmiHandler().(*mock.Handler)
	if !ok {
		return nil
	}
	return h
}

// pathsToTree builds a nested map tree from a flat map of gNMI path → value.
// Path segments are split on "/" and list entries like "Inst-list[moduleNum=1]"
// are kept as-is so each instance is a distinct branch. When a path segment is
// both a leaf and an intermediate node the existing leaf value is moved under a
// "_value" key.
func pathsToTree(data map[string]interface{}) map[string]interface{} {
	tree := make(map[string]interface{})
	for path, val := range data {
		parts := strings.Split(path, "/")
		cur := tree
		for i, part := range parts {
			if part == "" {
				continue
			}
			if i == len(parts)-1 {
				cur[part] = val
			} else {
				if existing, ok := cur[part]; ok {
					if m, ok := existing.(map[string]interface{}); ok {
						cur = m
					} else {
						m := map[string]interface{}{"_value": existing}
						cur[part] = m
						cur = m
					}
				} else {
					m := make(map[string]interface{})
					cur[part] = m
					cur = m
				}
			}
		}
	}
	return tree
}

// printTree writes an indented text representation of a nested tree map to buf.
func printTree(buf *bytes.Buffer, tree map[string]interface{}, indent string) {
	keys := make([]string, 0, len(tree))
	for k := range tree {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := tree[k]
		if subtree, ok := v.(map[string]interface{}); ok {
			buf.WriteString(indent + k + "/\n")
			printTree(buf, subtree, indent+"  ")
		} else {
			buf.WriteString(fmt.Sprintf("%s%s: %v\n", indent, k, v))
		}
	}
}

// MockGnmiShow returns all path/value pairs stored in the mock gNMI handler
// as a nested tree (JSON when --json is passed, indented text otherwise).
func (agw *AgentGateway) MockGnmiShow(_ context.Context, msgData ipc.MessageData) string {
	logger.GetLogger().Debug("MockGnmiShow")

	h := agw.mockGnmiHandler()
	if h == nil {
		return "mock gNMI is not active (NXOS is enabled)"
	}

	data := h.GetAllData()

	tree := pathsToTree(data)

	if msgData.Flags["json"] == "true" {
		jsonBytes, err := json.MarshalIndent(tree, "", "  ")
		if err != nil {
			return fmt.Sprintf("Error marshalling JSON: %v", err)
		}
		return string(jsonBytes)
	}

	if len(data) == 0 {
		return "No mock gNMI data stored"
	}

	var buf bytes.Buffer
	printTree(&buf, tree, "")
	return buf.String()
}

// MockGnmiGet returns the value stored at the given path in the mock gNMI handler.
func (agw *AgentGateway) MockGnmiGet(_ context.Context, msgData ipc.MessageData) string {
	logger.GetLogger().Debug("MockGnmiGet")

	h := agw.mockGnmiHandler()
	if h == nil {
		return "mock gNMI is not active (NXOS is enabled)"
	}

	path := msgData.Flags["path"]
	if path == "" {
		return "path is required"
	}

	// Collect all entries matching the path (exact + children via prefix)
	results := h.GetDataByPrefix(path)
	if len(results) == 0 {
		return fmt.Sprintf("path %q not found", path)
	}

	if len(results) == 1 {
		for _, v := range results {
			jsonBytes, _ := json.Marshal(v)
			return string(jsonBytes)
		}
	}

	merged := make([]interface{}, 0, len(results))
	for _, v := range results {
		merged = append(merged, v)
	}
	jsonBytes, _ := json.Marshal(merged)
	return string(jsonBytes)
}

// MockGnmiSet stores a value at the given path and fires gNMI notifications.
func (agw *AgentGateway) MockGnmiSet(ctx context.Context, msgData ipc.MessageData) string {
	logger.GetLogger().Debug("MockGnmiSet")

	h := agw.mockGnmiHandler()
	if h == nil {
		return "mock gNMI is not active (NXOS is enabled)"
	}

	path := msgData.Flags["path"]
	if path == "" {
		return "path is required"
	}
	value := msgData.Flags["value"]
	if value == "" {
		return "value is required"
	}

	if err := h.SetAndNotify(ctx, path, value); err != nil {
		return fmt.Sprintf("Error setting path: %v", err)
	}
	return fmt.Sprintf("Set %q = %s", path, value)
}

// MockGnmiDelete removes a path from the mock gNMI handler and fires gNMI notifications.
func (agw *AgentGateway) MockGnmiDelete(ctx context.Context, msgData ipc.MessageData) string {
	logger.GetLogger().Debug("MockGnmiDelete")

	h := agw.mockGnmiHandler()
	if h == nil {
		return "mock gNMI is not active (NXOS is enabled)"
	}

	path := msgData.Flags["path"]
	if path == "" {
		return "path is required"
	}

	if err := h.DeleteAndNotify(ctx, path); err != nil {
		return fmt.Sprintf("Error deleting path: %v", err)
	}
	return fmt.Sprintf("Deleted %q", path)
}

// MockGnmiSetBulk sets multiple path/value pairs from a JSON-encoded map.
func (agw *AgentGateway) MockGnmiSetBulk(ctx context.Context, msgData ipc.MessageData) string {
	logger.GetLogger().Debug("MockGnmiSetBulk")

	h := agw.mockGnmiHandler()
	if h == nil {
		return "mock gNMI is not active (NXOS is enabled)"
	}

	entriesJSON := msgData.Flags["entries"]
	if entriesJSON == "" {
		return "entries is required"
	}

	var entries map[string]string
	if err := json.Unmarshal([]byte(entriesJSON), &entries); err != nil {
		return fmt.Sprintf("Error parsing entries: %v", err)
	}

	for path, value := range entries {
		if err := h.SetAndNotify(ctx, path, value); err != nil {
			return fmt.Sprintf("Error setting %q: %v", path, err)
		}
	}
	return fmt.Sprintf("Set %d path(s)", len(entries))
}

// defaultAffinity returns "0" (dynamic). The store determines pinning mode via
// isLbModePinning(); affinity 0 is valid in both symmetric_hash and dpu_pinning modes.
func defaultAffinity(_ interface {
	GetData(string) (interface{}, bool)
}) string {
	return "0"
}

// MockVrfAdd creates a VRF in the mock gNMI handler by sending global and service
// path notifications, then sets its affinity. Affinity defaults based on LB mode.
func (agw *AgentGateway) MockVrfAdd(ctx context.Context, msgData ipc.MessageData) string {
	logger.GetLogger().Debug("MockVrfAdd")

	h := agw.mockGnmiHandler()
	if h == nil {
		return "mock gNMI is not active (NXOS is enabled)"
	}

	name := msgData.Flags["name"]
	if name == "" {
		return "name is required"
	}

	affinity := msgData.Flags["affinity"]
	if affinity == "" {
		affinity = defaultAffinity(h)
	}

	globalPath := fmt.Sprintf("device:/System/inst-items/Inst-list[name=%s]/name", name)
	if err := h.SetAndNotify(ctx, globalPath, name); err != nil {
		return fmt.Sprintf("Error setting global VRF: %v", err)
	}

	servicePath := fmt.Sprintf("device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/fwpolicy-items/ipvrf-items/dom-items/Dom-list[name=%s]/name", name)
	if err := h.SetAndNotify(ctx, servicePath, name); err != nil {
		return fmt.Sprintf("Error setting service VRF: %v", err)
	}

	affinityPath := fmt.Sprintf("device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/fwpolicy-items/ipvrf-items/dom-items/Dom-list[name=%s]/affinity", name)
	if err := h.SetAndNotify(ctx, affinityPath, affinity); err != nil {
		return fmt.Sprintf("Error setting VRF affinity: %v", err)
	}

	return fmt.Sprintf("VRF %q added (affinity=%s)", name, affinity)
}

// MockVrfDelete removes a VRF from the mock gNMI handler by deleting both
// global and service path entries.
func (agw *AgentGateway) MockVrfDelete(ctx context.Context, msgData ipc.MessageData) string {
	logger.GetLogger().Debug("MockVrfDelete")

	h := agw.mockGnmiHandler()
	if h == nil {
		return "mock gNMI is not active (NXOS is enabled)"
	}

	name := msgData.Flags["name"]
	if name == "" {
		return "name is required"
	}

	globalPath := fmt.Sprintf("device:/System/inst-items/Inst-list[name=%s]", name)
	if err := h.DeleteAndNotify(ctx, globalPath); err != nil {
		return fmt.Sprintf("Error deleting global VRF: %v", err)
	}

	servicePath := fmt.Sprintf("device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/fwpolicy-items/ipvrf-items/dom-items/Dom-list[name=%s]", name)
	if err := h.DeleteAndNotify(ctx, servicePath); err != nil {
		return fmt.Sprintf("Error deleting service VRF: %v", err)
	}

	return fmt.Sprintf("VRF %q deleted", name)
}

// MockVlanAdd creates a VLAN in the mock gNMI handler by sending global and service
// path notifications, then sets its affinity. Affinity defaults based on LB mode.
func (agw *AgentGateway) MockVlanAdd(ctx context.Context, msgData ipc.MessageData) string {
	logger.GetLogger().Debug("MockVlanAdd")

	h := agw.mockGnmiHandler()
	if h == nil {
		return "mock gNMI is not active (NXOS is enabled)"
	}

	id := msgData.Flags["id"]
	if id == "" {
		return "id is required"
	}

	affinity := msgData.Flags["affinity"]
	if affinity == "" {
		affinity = defaultAffinity(h)
	}

	fabEncap := fmt.Sprintf("vxlan-%s", id)
	globalPath := fmt.Sprintf("device:/System/bd-items/bd-items/BD-list[fabEncap=%s]/fabEncap", fabEncap)
	if err := h.SetAndNotify(ctx, globalPath, fabEncap); err != nil {
		return fmt.Sprintf("Error setting global VLAN: %v", err)
	}

	servicePath := fmt.Sprintf("device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/fwpolicy-items/bd-items/vlan-items/Vlan-list[vlanId=%s]/vlanId", id)
	if err := h.SetAndNotify(ctx, servicePath, id); err != nil {
		return fmt.Sprintf("Error setting service VLAN: %v", err)
	}

	affinityPath := fmt.Sprintf("device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/fwpolicy-items/bd-items/vlan-items/Vlan-list[vlanId=%s]/affinity", id)
	if err := h.SetAndNotify(ctx, affinityPath, affinity); err != nil {
		return fmt.Sprintf("Error setting VLAN affinity: %v", err)
	}

	return fmt.Sprintf("VLAN %q added (affinity=%s)", id, affinity)
}

// MockVlanDelete removes a VLAN from the mock gNMI handler by deleting both
// global and service path entries.
func (agw *AgentGateway) MockVlanDelete(ctx context.Context, msgData ipc.MessageData) string {
	logger.GetLogger().Debug("MockVlanDelete")

	h := agw.mockGnmiHandler()
	if h == nil {
		return "mock gNMI is not active (NXOS is enabled)"
	}

	id := msgData.Flags["id"]
	if id == "" {
		return "id is required"
	}

	fabEncap := fmt.Sprintf("vxlan-%s", id)
	globalPath := fmt.Sprintf("device:/System/bd-items/bd-items/BD-list[fabEncap=%s]", fabEncap)
	if err := h.DeleteAndNotify(ctx, globalPath); err != nil {
		return fmt.Sprintf("Error deleting global VLAN: %v", err)
	}

	servicePath := fmt.Sprintf("device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/fwpolicy-items/bd-items/vlan-items/Vlan-list[vlanId=%s]", id)
	if err := h.DeleteAndNotify(ctx, servicePath); err != nil {
		return fmt.Sprintf("Error deleting service VLAN: %v", err)
	}

	return fmt.Sprintf("VLAN %q deleted", id)
}
