package fwa

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"

	"github.com/isovalent/hubble-fgs/pkg/config"
	"github.com/isovalent/hubble-fgs/pkg/model/server/dpu"
	"github.com/isovalent/hubble-fgs/pkg/nxos"
)

const (
	BUFSIZE   = 4096
	ENV_TOKEN = "HYPERSHIELD_TOKEN"

	dpuTimeout = 300 // in second
	AgentCount = 4

	AgentIdDpu1 = "169.254.24.1"
	AgentIdDpu2 = "169.254.28.1"
	AgentIdDpu3 = "169.254.32.1"
	AgentIdDpu4 = "169.254.36.1"
)

var (
	Agent = newAgent()
)

func newAgent() *FWAgent {
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

	return &FWAgent{
		Cfg:         &config.Config{},
		serviceMac:  mac,
		dpuPortLow:  uint16(dpuLow),
		dpuPortHigh: uint16(dpuHigh),
		cpaPortLow:  uint16(cpaLow),
		cpaPortHigh: uint16(cpaHigh),
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
	go fwa.DpuHealthCheck(ctx)
	err := nxos.Nexus.Setup(ctx, fwa.dpuPortLow, fwa.dpuPortHigh)
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
	server := dpu.GetDPUListener()
	retries := 0
	maxRetries := 6
	healthCheckTimer := 10 * time.Second

	for {
		select {
		case <-ctx.Done():
			logger.GetLogger().Info("Stop DPU health checker")
			return
		case <-time.After(healthCheckTimer):
			ok := server.StateCheck()
			if !ok {
				retries++
				if retries > maxRetries {
					logger.GetLogger().Error("DPU out of sync!")
				}
			} else {
				retries = 0
			}
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
	server := dpu.GetDPUListener()
	return server.StatusReportString()
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

type DpuConfig struct {
	ServiceIp  string `json:"serviceIp"`
	ServiceMac string `json:"serviceMac"`
	PortLow    uint16 `json:"portLow"`
	PortHigh   uint16 `json:"portHigh"`
}

func (fwa *FWAgent) GetDpuConfig(_ context.Context, agentId string) []byte {
	portCount := (fwa.dpuPortHigh - fwa.dpuPortLow + 1) / AgentCount
	conf := DpuConfig{
		ServiceMac: fwa.serviceMac,
		ServiceIp:  nxos.Nexus.GetServiceIp(),
	}
	var index uint16
	switch agentId {
	case AgentIdDpu1:
		index = 0

	case AgentIdDpu2:
		index = 1

	case AgentIdDpu3:
		index = 2

	case AgentIdDpu4:
		index = 3

	default:
		return []byte{}
	}
	conf.PortLow = fwa.dpuPortLow + portCount*index
	conf.PortHigh = fwa.dpuPortLow + portCount*(index+1) - 1

	jstr, err := json.Marshal(conf)
	if err != nil {
		logger.GetLogger().Error("Fail to marshal", logfields.Error, err)
		return []byte{}
	}
	return jstr
}
