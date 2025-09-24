package fwa

import (
	"context"
	"encoding/json"
	"errors"
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
)

const (
	BUFSIZE   = 4096
	ENV_TOKEN = "HYPERSHIELD_TOKEN"

	// dpuTimeout = 300 // in second
)

func NewAgent(dpuListener *dpu.DPUListener) *FWAgent {
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
	dpuConfig.ServiceMac = mac
	dpuConfig.PortLow = uint32(dpuLow)
	dpuConfig.PortHigh = uint32(dpuHigh)
	configObj := &v1alpha.ConfigObject{
		Type:   v1alpha.ConfigType_CONFIG_TYPE_DPU,
		Config: &v1alpha.ConfigObject_ConfigDpu{ConfigDpu: &dpuConfig},
	}
	library.GetRepository().AddConfig(configObj)

	return &FWAgent{
		Cfg:         &config.Config{},
		serviceMac:  mac,
		dpuPortLow:  uint16(dpuLow),
		dpuPortHigh: uint16(dpuHigh),
		cpaPortLow:  uint16(cpaLow),
		cpaPortHigh: uint16(cpaHigh),
		dpuListener: dpuListener,
	}
}

type FWAgent struct {
	AgentId      string
	Name         string
	version      string
	Ip           string
	Hostname     string
	Architecture string
	Os           string
	SerialNumber string

	Cfg *config.Config

	//serviceIp   string // looks necessary but not used yet
	serviceMac  string
	dpuPortLow  uint16
	dpuPortHigh uint16
	cpaPortLow  uint16
	cpaPortHigh uint16

	dpuListener *dpu.DPUListener

	sync.RWMutex
}

func (fwa *FWAgent) Id() string {
	return fwa.AgentId
}

func (fwa *FWAgent) Version() string {
	return fwa.version
}

func (fwa *FWAgent) KeepAliveInterval() int {
	return fwa.Cfg.Agent.KeepAliveInterval
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

func (fwa *FWAgent) Config(_ context.Context, path string) error {
	// Collecting agent metadata
	var err error
	fwa.Ip, err = getOutboundIP()
	if err != nil {
		logger.GetLogger().Error("Failed to get machine IP address", logfields.Error, err)
	}
	fwa.Hostname, err = os.Hostname()
	if err != nil {
		logger.GetLogger().Error("Failed to get machine hostname", logfields.Error, err)
	}
	fwa.Architecture = runtime.GOARCH
	fwa.Os = runtime.GOOS

	// Setting up config
	created, err := fwa.Cfg.Init(path)
	if err != nil {
		logger.GetLogger().Error("Failed to initialize config", logfields.Error, err)
		return err
	}
	if created {
		logger.GetLogger().Info("Config file not found, new config file created", "path", path)
	} else {
		logger.GetLogger().Info("Config file found", "path", path)
	}

	fwa.AgentId = fwa.Cfg.Agent.AgentId
	// HACK for cpa container scheduling/resource issue
	fwa.Cfg.Agent.KeepAliveInterval = 10

	return nil
}

func (fwa *FWAgent) Setup(ctx context.Context) error {
	err := nxos.Nexus.Setup(ctx, fwa.dpuPortLow, fwa.dpuPortHigh, fwa.dpuListener)
	if err != nil {
		logger.Fatal(logger.GetLogger(), "NXOS setup fails")
	}

	return nil
}

func (fwa *FWAgent) Register(ctx context.Context) error {
	// Extracting logger and agent from context
	nxos.Nexus.SetRegOk(ctx, nxos.RegOk)
	return nil
}

// --------------------- DPU related
func (fwa *FWAgent) DpuHealthCheck(ctx context.Context) {
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
			ok := fwa.dpuListener.StateCheck()
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
			ok, cnt := fwa.dpuListener.HealthCheck()
			nxos.DpuHealth(ctx, ok, cnt)
		}
	}
}

func (fwa *FWAgent) LoadPolicies(_ context.Context, pols string) string {
	logger.GetLogger().Debug("Loading policies:", "policy", pols)

	return "TBD"
}

func (fwa *FWAgent) ShowPolicies(_ context.Context) string {
	logger.GetLogger().Debug("Show policies")
	return "TBD"
}

func (fwa *FWAgent) ShowDpu(_ context.Context) string {
	logger.GetLogger().Debug("Show dpu")
	return fwa.dpuListener.StatusReportString()
}

func (fwa *FWAgent) PingFwa(_ context.Context, dpu string) string {
	logger.GetLogger().Debug("Ping DPU", "uid", dpu)
	return ""
}

func (fwa *FWAgent) Reopen(_ context.Context) string {
	logger.GetLogger().Debug("Reopen")
	return "Reopen ok"
}

func (fwa *FWAgent) ShowTokens(_ context.Context) string {
	logger.GetLogger().Debug("Show tokens")
	return ""
}

func (fwa *FWAgent) ShowSyslog(_ context.Context) (string, error) {
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

func (fwa *FWAgent) LoadSyslog(_ context.Context, syslog string) error {
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
