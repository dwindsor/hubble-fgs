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

	"github.com/isovalent/hubble-fgs/pkg/config"
	"github.com/isovalent/hubble-fgs/pkg/config/library"
	"github.com/isovalent/hubble-fgs/pkg/dpu/policy"
	"github.com/isovalent/hubble-fgs/pkg/ipc"
	"github.com/isovalent/hubble-fgs/pkg/model/switchpolicy"
	"github.com/isovalent/hubble-fgs/pkg/model/switchstatus"
	"github.com/isovalent/hubble-fgs/pkg/nxos"
	"github.com/isovalent/hubble-fgs/pkg/shutdown"
	"github.com/isovalent/hubble-fgs/pkg/token"
)

const (
	BUFSIZE        = 4096
	TOKEN_INTERVAL = 2
	CHECK_INTERVAL = 3 // in second

	// dpuTimeout = 300 // in second
)

func NewAgent(dpuListener *switchpolicy.DPUListener, policyHandler switchpolicy.PolicyHandler) *AgentGateway {
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
	library.GetRepository().AddConfigCallback(v1alpha.ConfigType_CONFIG_TYPE_LOG_IPFIX, dpuListener.SubscribeConfig)
	library.GetRepository().AddConfigCallback(v1alpha.ConfigType_CONFIG_TYPE_LOG_TIMESCAPE, dpuListener.SubscribeConfig)
	library.GetRepository().AddConfigCallback(v1alpha.ConfigType_CONFIG_TYPE_LOG_SPLUNK, dpuListener.SubscribeConfig)

	// Setting up dpu config atomically
	// dpuConfig.ServiceIp is populated by nxos package
	// dpuConfig.HaIp is populated by nxos package
	err := library.GetRepository().UpdateConfig(v1alpha.ConfigType_CONFIG_TYPE_DPU, func(existing *v1alpha.ConfigObject) (*v1alpha.ConfigObject, error) {
		var dpuConfig *v1alpha.DpuConfig
		if existing != nil && existing.GetConfigDpu() != nil {
			dpuConfig = existing.GetConfigDpu()
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
		StartupTime:   startupTime,
		serviceMac:    mac,
		dpuPortLow:    uint16(dpuLow),
		dpuPortHigh:   uint16(dpuHigh),
		cpaPortLow:    uint16(cpaLow),
		cpaPortHigh:   uint16(cpaHigh),
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

	//serviceIp   string // looks necessary but not used yet
	serviceMac  string
	dpuPortLow  uint16
	dpuPortHigh uint16
	cpaPortLow  uint16
	cpaPortHigh uint16

	dpuListener      *switchpolicy.DPUListener
	PolicyHandler    switchpolicy.PolicyHandler
	InventoryHandler switchstatus.InventoryHandler

	sync.RWMutex
}

func (agw *AgentGateway) Id() string {
	return agw.AgentId
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

	return nil
}

func (agw *AgentGateway) GetNxHeadlessMode() bool {
	return nxos.Nexus.GetHeadlessMode()
}

// GetNxProxyConfig retrieves the proxy configuration from the Nexus system.
func (agw *AgentGateway) GetNxProxyConfig(ctx context.Context) error {
	return nxos.Nexus.GetProxyConfig(ctx)
}

func (agw *AgentGateway) GetControllerConnectionStatus() int64 {
	return int64(nxos.Nexus.GetControllerConnectionStatus())
}

func (agw *AgentGateway) GetSerialNumber(ctx context.Context) string {
	if agw.SerialNumber == "" {
		return nxos.Nexus.GetSerialNum(ctx)
	}
	return agw.SerialNumber
}

func (agw *AgentGateway) Setup(ctx context.Context) error {
	err := nxos.Nexus.Setup(ctx, agw.dpuPortLow, agw.dpuPortHigh, agw.dpuListener, agw.PolicyHandler)
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
	nxos.Nexus.ResetReg(ctx)
	if !status {
		nxos.Nexus.SetRegFail(ctx, nxos.RegFailK8sAuth)
		nxos.Nexus.SetConnFail(ctx, nxos.ConnFailed)
	} else {
		nxos.Nexus.SetRegOk(ctx, nxos.RegOk)
		nxos.Nexus.SetConnOk(ctx, nxos.ConnOk)
	}
}

func (agw *AgentGateway) ResetConnectionStatus(ctx context.Context) {
	nxos.Nexus.ResetConn(ctx)
}

func (agw *AgentGateway) SetConnectionStatus(ctx context.Context, status bool, nxosMode bool) {
	logger.GetLogger().Debug("Setting connection status", "status", status)
	if !nxosMode {
		// Running in non-NXOS mode.
		return
	}

	if status {
		nxos.Nexus.SetConnOk(ctx, nxos.ConnOk)
	} else {
		nxos.Nexus.SetConnFail(ctx, nxos.ConnFailed)
	}

	notifyHA(ctx, status)
}

// notifyHA notifies the high availability system about
// the controller connection current status.
func notifyHA(ctx context.Context, status bool) {
	nxos.Nexus.NotifyWatching(ctx, status)
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
	// Ignore restart request from nxos.SetToken, since token is set via agw command line.
	_, err := nxos.Nexus.SetToken(ctx, token)
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
// then repeatedly tries to load or authenticate using Kubernetes until successful
// or until the provided context is cancelled. If the token path is not set in the
// configuration, it returns an error immediately. The function returns true if
// authentication data is loaded successfully, or false and an error otherwise.
func (agw *AgentGateway) LoadAuth(ctx context.Context) (bool, error) {
	logger.GetLogger().Debug("loading authentication data")
	// Setting token path.
	if agw.Cfg.Env.TokenPath != "" {
		agw.Token.SetK8sAuthPath(agw.Cfg.Env.TokenPath)
	} else {
		return false, fmt.Errorf("config TokenPath is empty")
	}

	// Finding and setting Token.
	registered := make(chan bool)
	go func() {
		// Try getting authentication immediately first
		reg, err := agw.tryLoadK8sAuth()
		if err == nil {
			registered <- reg
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
					registered <- reg
					return
				}
			}
		}
	}()

	// Waiting for tokens to be loaded.
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case reg := <-registered:
		return reg, nil
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

func (agw *AgentGateway) WaitForInService(ctx context.Context) {
	logger.GetLogger().Debug("WaitForInService")

	for {

		if nxos.Nexus.IsInService(ctx) {
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
			logger.GetLogger().Debug("DPU health check - starting")
			ok := agw.dpuListener.StateCheck()
			if !ok {
				retries++
				if retries > maxRetries {
					nxos.DpuInSync(ctx, false)
					logger.GetLogger().Error("DPU out of sync!")
				}
			} else {
				nxos.DpuInSync(ctx, true)
				retries = 0
			}
			ok, cnt := agw.dpuListener.HealthCheck()
			nxos.DpuHealth(ctx, ok, cnt)
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
	state := switchpolicy.NewState()

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
	if err := state.SetL3Networks(currentL3Networks); err != nil {
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

	vrfs := nxos.Nexus.GetVrfs()
	gids := nxos.Nexus.GetGids()

	// Temporary helper object for sorting
	type vrfWithGid struct {
		gid    uint16
		hasGid bool
		name   string
		vrf    nxos.VrfBd
	}
	vrfList := make([]vrfWithGid, 0, len(vrfs))
	for name, vrf := range vrfs {
		gid, hasGid := gids[name]
		vrfList = append(vrfList, vrfWithGid{gid: gid, hasGid: hasGid, name: name, vrf: vrf})
	}

	// Sort by global ID - VRFs with GIDs first (sorted by GID), then VRFs without GIDs (sorted by name)
	sort.Slice(vrfList, func(i, j int) bool {
		// If both have GIDs, sort by GID
		if vrfList[i].hasGid && vrfList[j].hasGid {
			return vrfList[i].gid < vrfList[j].gid
		}
		// If only i has GID, it comes first
		if vrfList[i].hasGid {
			return true
		}
		// If only j has GID, it comes first
		if vrfList[j].hasGid {
			return false
		}
		// Neither has GID, sort by name
		return vrfList[i].name < vrfList[j].name
	})

	for _, v := range vrfList {
		gidStr := ""
		if v.hasGid {
			gidStr = fmt.Sprintf("%d", v.gid)
		}

		affinityStr := ""
		if v.vrf.Affinity != 0 && v.vrf.IsStatic {
			affinityStr = fmt.Sprintf("%d", v.vrf.Affinity)
		}

		pinnedStr := "N/A"
		if nxos.Nexus.IsLbModePinning(ctx) {
			pinnedStr = fmt.Sprintf("%d", v.vrf.DpuPinned)
		}

		fmt.Fprintf(w, "%s\t%s\t%t\t%t\t%t\t%s\t%s\n",
			gidStr,
			v.name,
			v.vrf.IsGlobal,
			v.vrf.IsService,
			v.vrf.IsStatic,
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

func validateDpuConfig(dpuConfig *DpuConfigData) error {
	if dpuConfig == nil {
		return errors.New("dpu config is nil")
	}

	ip := net.ParseIP(dpuConfig.ServiceIP)
	if ip == nil || ip.To4() == nil {
		logger.GetLogger().Debug("Invalid ipv4 format service_ip", "ip", dpuConfig.ServiceIP)
		return errors.New("invalid ipv4 format for service_ip")
	}
	if dpuConfig.ServiceMAC == "" {
		logger.GetLogger().Debug("Invalid mac address format service_mac", "mac", dpuConfig.ServiceMAC)
		return errors.New("invalid mac address format for service_mac")
	}

	return nil
}

func (agw *AgentGateway) LoadConfigDpu(_ context.Context, dpu string) error {
	logger.GetLogger().Debug("Load dpu", "dpu", dpu)

	// Unmarshal the JSON string into DpuConfig
	var dpuConfig DpuConfigData
	err := json.Unmarshal([]byte(dpu), &dpuConfig)
	if err != nil {
		logger.GetLogger().Error("Failed to unmarshal dpu JSON", "error", err)
		return err
	}

	// Validate dpu config
	err = validateDpuConfig(&dpuConfig)
	if err != nil {
		logger.GetLogger().Error("Failed to validate dpu config", "error", err)
		return err
	}

	// Convert to DPU config object
	configObj := &v1alpha.ConfigObject{
		Type:   v1alpha.ConfigType_CONFIG_TYPE_DPU,
		Source: v1alpha.ConfigSource_CONFIG_SOURCE_LOCAL,
		Config: &v1alpha.ConfigObject_ConfigDpu{
			ConfigDpu: &v1alpha.DpuConfig{
				ServiceIp:  dpuConfig.ServiceIP,
				ServiceMac: dpuConfig.ServiceMAC,
				PortLow:    dpuConfig.PortLow,
				PortHigh:   dpuConfig.PortHigh,
			},
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
		syslogConfig.Configs[logConfig.Id] = &v1alpha.LogConfig{
			Id:          logConfig.Id,
			Name:        logConfig.Name,
			Description: logConfig.Description,
			Host:        logConfig.Config.Host,
			Port:        logConfig.Config.Port,
			Mode:        logConfig.Config.Mode,
			Tls:         logConfig.Config.Tls,
			Token:       logConfig.Secrets.Token,
			Username:    logConfig.Secrets.Username,
			Password:    logConfig.Secrets.Password,
			Ca:          logConfig.Secrets.CA,
			Cert:        logConfig.Secrets.Cert,
			Key:         logConfig.Secrets.Key,
			KeyPassword: logConfig.Secrets.KeyPassword,
		}
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
		config.Type != LogTypeSplunk &&
		config.Type != LogTypeIpfix {
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

	// Check mode
	if config.Config.Mode == "" {
		return config, errors.New("log mode is required")
	}
	if strings.ToLower(config.Config.Mode) != "tcp" && strings.ToLower(config.Config.Mode) != "udp" {
		return config, errors.New("invalid mode: must be 'tcp' or 'udp'")
	}

	return config, nil
}
