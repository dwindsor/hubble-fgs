package agw

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"

	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"

	"github.com/isovalent/hubble-fgs/pkg/config"
	"github.com/isovalent/hubble-fgs/pkg/config/library"
	"github.com/isovalent/hubble-fgs/pkg/model/server/dpu"
	"github.com/isovalent/hubble-fgs/pkg/nxos"
	"github.com/isovalent/hubble-fgs/pkg/token"
)

const (
	BUFSIZE        = 4096
	TOKEN_INTERVAL = 2

	// dpuTimeout = 300 // in second
)

func NewAgent(dpuListener *dpu.DPUListener) *AgentGateway {
	mac := os.Getenv("NX_SAS_RMAC")
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

	// Getting latest dpu config in case it was updated
	var dpuConfig v1alpha.DpuConfig
	err := library.GetRepository().GetConfig(v1alpha.ConfigType_CONFIG_TYPE_DPU, &dpuConfig)
	if err != nil && !library.IsConfigNotFound(err) {
		logger.GetLogger().Error("Failed to get dpu config, requires restart", "error", err)
	}

	// Setting up dpu config
	// dpuConfig.ServiceIp is populated by nxos package
	dpuConfig.ServiceIp = "169.251.31.135" // FIXME:
	dpuConfig.ServiceMac = mac
	dpuConfig.PortLow = uint32(dpuLow)
	dpuConfig.PortHigh = uint32(dpuHigh)
	configObj := &v1alpha.ConfigObject{
		Type:   v1alpha.ConfigType_CONFIG_TYPE_DPU,
		Config: &v1alpha.ConfigObject_ConfigDpu{ConfigDpu: &dpuConfig},
	}
	library.GetRepository().AddConfig(configObj)

	return &AgentGateway{
		Cfg:         &config.Config{},
		Token:       &token.AgentToken{},
		serviceMac:  mac,
		dpuPortLow:  uint16(dpuLow),
		dpuPortHigh: uint16(dpuHigh),
		cpaPortLow:  uint16(cpaLow),
		cpaPortHigh: uint16(cpaHigh),
		dpuListener: dpuListener,
	}
}

type AgentGateway struct {
	AgentId      string
	Name         string
	version      string
	Ip           string
	Hostname     string
	Architecture string
	Os           string
	SerialNumber string

	Cfg   *config.Config
	Token *token.AgentToken

	//serviceIp   string // looks necessary but not used yet
	serviceMac  string
	dpuPortLow  uint16
	dpuPortHigh uint16
	cpaPortLow  uint16
	cpaPortHigh uint16

	dpuListener *dpu.DPUListener

	sync.RWMutex
}

func (agw *AgentGateway) Id() string {
	return agw.AgentId
}

func (agw *AgentGateway) Version() string {
	return agw.version
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

func (agw *AgentGateway) Setup(ctx context.Context) error {
	err := nxos.Nexus.Setup(ctx, agw.dpuPortLow, agw.dpuPortHigh, agw.dpuListener)
	if err != nil {
		logger.Fatal(logger.GetLogger(), "NXOS setup failed")
	}

	return nil
}

func (agw *AgentGateway) Register(ctx context.Context) error {
	nxos.Nexus.SetRegOk(ctx, nxos.RegOk)
	nxos.Nexus.SetConnOk(ctx, nxos.ConnOk)
	return nil
}

// SetK8sCtlrAuthToken sets the Kubernetes controller authentication token in both the AgentToken and Nxos structs,
// and persists the token if possible. Returns an error if the operation fails.
func (agw *AgentGateway) SetK8sCtlrAuthToken(token string) error {
	logger.GetLogger().Debug("setting k8s auth token")

	// Set the token in both the AgentToken and Nxos structs
	if err := nxos.Nexus.SetToken(token); err != nil {
		return fmt.Errorf("failed to set nxos k8s auth token: %w", err)
	}

	if agw.Token != nil {
		// Set the token path if not already set.
		if agw.Cfg.Env.TokenPath == "" {
			return fmt.Errorf("config TokenPath is not set")
		} else if agw.Cfg.Env.TokenPath != agw.Token.K8sAuthPath() {
			agw.Token.SetK8sAuthPath(agw.Cfg.Env.TokenPath)
		}
		// Set and persist the token.
		agw.Token.SetK8sAuthToken(token)
		if err := agw.Token.Persist(); err != nil {
			return fmt.Errorf("failed to persist token: %w", err)
		}
	} else {
		return fmt.Errorf("failed to set AgentToken")
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
		for {
			reg, err := agw.tryLoadK8sAuth()
			if err == nil {
				registered <- reg
				return
			}
			time.Sleep(TOKEN_INTERVAL * time.Second)
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

	if valid := agw.Token.ValidK8sAuth(); !valid {
		logger.GetLogger().Error("failed to parse k8s auth token", logfields.Error, err)
		return false, err
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
			return false, fmt.Errorf("failed to persist token: %w", err)
		}
	}

	if err := agw.Cfg.Reload(); err != nil {
		logger.GetLogger().Error("failed to reload config", logfields.Error, err)
		return false, err
	}
	return true, nil
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
			logger.GetLogger().Debug("DPU health check")
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

func (agw *AgentGateway) LoadPolicies(_ context.Context, pols string) string {
	logger.GetLogger().Debug("Loading policies:", "policy", pols)

	return "TBD"
}

func (agw *AgentGateway) ShowPolicies(_ context.Context) string {
	logger.GetLogger().Debug("Show policies")
	return "TBD"
}

func (agw *AgentGateway) ShowDpu(_ context.Context) string {
	logger.GetLogger().Debug("Show dpu")
	return agw.dpuListener.StatusReportString()
}

func (agw *AgentGateway) PingFwa(_ context.Context, dpu string) string {
	logger.GetLogger().Debug("Ping DPU", "uid", dpu)
	return ""
}

func (agw *AgentGateway) Reopen(_ context.Context) string {
	logger.GetLogger().Debug("Reopen")
	return "Reopen ok"
}

func (agw *AgentGateway) ShowTokens(_ context.Context) string {
	logger.GetLogger().Info("Show tokens")
	agw.RLock()
	defer agw.RUnlock()

	if agw.Token != nil {
		at := agw.Token.K8sAuthToken()
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
