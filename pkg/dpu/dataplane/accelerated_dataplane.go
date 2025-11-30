package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"

	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"

	dpAppPolicy "github.com/isovalent/hubble-fgs/pkg/dpu/policy"
	"github.com/isovalent/hubble-fgs/pkg/dpu/socket"
	"github.com/isovalent/hubble-fgs/pkg/model/switchpolicy"
)

// Returns a newly created accelerated dataplane object
//
// Parameters:
//   - id: string
//   - apiPath: string
//   - persistPath: string
func NewAcceleratedDataplane(id, apiPath string) *AcceleratedDataplane {
	return &AcceleratedDataplane{
		Accelerated: &AcceleratedDataplaneProcess{
			Id:      id,
			ApiPath: apiPath,
		},
	}
}

// -----------------------------------------------------------------------------
// Individual Dataplane Implementation
// -----------------------------------------------------------------------------

type AcceleratedDataplaneProcess struct {
	Id      string
	ApiPath string
	Version string
	Asic    string
	NpuIp   string
	NpuMac  string
	Status  atomic.Bool
}

func (dp *AcceleratedDataplaneProcess) GetId() string {
	return dp.Id
}

func (dp *AcceleratedDataplaneProcess) Init(_ context.Context) error {
	type switchObj struct {
		Sw struct {
			Version string `json:"version"`
		} `json:"sw"`
	}

	// Getting the version of the DPU, setting it to "missing" if it fails
	dp.Version = "missing"
	versionFile, err := os.ReadFile("/nic/etc/VERSION.json")
	if err != nil {
		logger.GetLogger().Error("failed to read DPU version file", logfields.Error, err)
	} else {
		var versionObj switchObj
		err := json.Unmarshal(versionFile, &versionObj)
		if err != nil {
			logger.GetLogger().Error("failed to get DPU version", logfields.Error, err)
		} else {
			dp.Version = versionObj.Sw.Version
		}
	}

	// Getting the DPU board type (can't get from asic field in the file above because it is not updated correctly)
	dp.Asic = "missing"
	boardType, err := runCommand("/nic/bin/board_config", "-b")
	if err != nil {
		logger.GetLogger().Error("failed to get DPU board type", logfields.Error, err)
	}
	boardType = strings.TrimSpace(boardType)
	asic, ok := dpuBoardMap[boardType]
	if ok {
		dp.Asic = asic
	}
	return nil
}

func (dp *AcceleratedDataplaneProcess) Start(ctx context.Context) error {
	// Setting status to true
	dp.Status.Store(true)

	// Wait for dataplane unix socket to be created
	backoff := 100 * time.Millisecond
	maxBackoff := 5 * time.Second
	for {
		_, err := os.Stat(dp.ApiPath)
		if err == nil {
			break
		}
		logger.GetLogger().Info("Waiting for dataplane unix socket to be created", "path", dp.ApiPath, "error", err, "backoff", backoff)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		// Exponential backoff with max cap
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
	return nil
}

func (dp *AcceleratedDataplaneProcess) Stop(_ context.Context) error {
	// Setting status to false
	dp.Status.Store(false)
	return nil
}

func (dp *AcceleratedDataplaneProcess) UpdateFirewallPolicies(_ context.Context, policyMsg *dpAppPolicy.FwPolicyMsgV2) error {
	// Applying policy to the dataplane
	msg := &socket.ControlMessage{
		Command: UpdatePolicy,
		Type:    socket.POLICY,
		Data:    json.RawMessage(dpAppPolicy.ConvertPolicyMsgToJson(policyMsg)),
	}

	dpsocket := socket.NewDataplaneSocket(dp.ApiPath, UDS_TIMEOUT*time.Second)
	err := dpsocket.Connect()
	if err != nil {
		logger.GetLogger().Error("failed to connect to dataplane", logfields.Error, err)
		return err
	}
	defer dpsocket.Close()
	err = dpsocket.Send(msg)
	if err != nil {
		logger.GetLogger().Error("failed to send policy to dataplane", logfields.Error, err)
		return err
	}
	rc, err := dpsocket.Receive()
	if err != nil {
		logger.GetLogger().Error("failed to receive response from dataplane", logfields.Error, err)
		return err
	}
	if rc.ReturnCode < socket.SUCCESS {
		logger.GetLogger().Error("failed to apply policies to dataplane", "errorCode", rc.ReturnCode.String())
		return errors.New(rc.ReturnCode.String())
	}
	logger.GetLogger().Debug("dataplane policy updated")
	return nil
}

func (dp *AcceleratedDataplaneProcess) ClearFirewallPolicies(_ context.Context) error {
	// Clearing policy to the dataplane
	msg := &socket.ControlMessage{
		Command: ClearPolicy,
		Type:    socket.POLICY,
	}

	dpsocket := socket.NewDataplaneSocket(dp.ApiPath, UDS_TIMEOUT*time.Second)
	err := dpsocket.Connect()
	if err != nil {
		logger.GetLogger().Error("failed to connect to dataplane", logfields.Error, err)
		return err
	}
	defer dpsocket.Close()
	err = dpsocket.Send(msg)
	if err != nil {
		logger.GetLogger().Error("failed to send clear policy to dataplane", logfields.Error, err)
		return err
	}
	rc, err := dpsocket.Receive()
	if err != nil {
		logger.GetLogger().Error("failed to receive response from dataplane", logfields.Error, err)
		return err
	}
	if rc.ReturnCode < socket.SUCCESS {
		logger.GetLogger().Error("failed to clear policies from dataplane", "errorCode", rc.ReturnCode.String())
		return errors.New(rc.ReturnCode.String())
	}
	logger.GetLogger().Debug("dataplane policy cleared")
	return nil
}

func (dp *AcceleratedDataplaneProcess) SendDpuConfig(dpuConfig *v1alpha.DpuConfig) error {
	cfg := DataplaneDpuConfig{
		NpuIP:  dpuConfig.ServiceIp,
		NpuMAC: dpuConfig.ServiceMac,
	}
	if cfg.NpuIP == "" || cfg.NpuMAC == "" {
		logger.GetLogger().Error("failed to send dpu config", "npuIp", cfg.NpuIP, "npuMac", cfg.NpuMAC)
		return fmt.Errorf("failed to send dpu config")
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		logger.GetLogger().Error("failed to marshal dpu config", logfields.Error, err)
		return fmt.Errorf("failed to marshal dpu config")
	}
	logger.GetLogger().Info("sending dpu config to dp-app", "config", string(data))

	// Sending dpu configuration to the accelerated dataplane
	msg := &socket.ControlMessage{
		Command: Dataplane_DpuConfig,
		Type:    socket.DATAPLANE,
		Data:    data,
	}
	dpsocket := socket.NewDataplaneSocket(dp.ApiPath, UDS_TIMEOUT*time.Second)
	err = dpsocket.Connect()
	if err != nil {
		return err
	}
	defer dpsocket.Close()
	err = dpsocket.Send(msg)
	if err != nil {
		return err
	}
	rc, err := dpsocket.Receive()
	if err != nil {
		return err
	}
	if rc.ReturnCode < socket.SUCCESS {
		return errors.New(rc.ReturnCode.String())
	}
	logger.GetLogger().Debug("dataplane dpu config updated")
	return nil
}

func (dp *AcceleratedDataplaneProcess) SendLogConfig(logConfigs map[string]*v1alpha.LogConfig) error {
	// Building config object
	logConfig := LogConfig{}
	if len(logConfigs) == 0 {
		logConfig.LogEnabled = false
		logConfig.DataplaneLevel = "info"
		logConfig.Collector = []LogCollector{}
	} else {
		logConfig.LogEnabled = true
		logConfig.DataplaneLevel = "info"
		for _, log := range logConfigs {
			port, err := strconv.Atoi(log.Port)
			if err != nil {
				return fmt.Errorf("failed to convert syslog port to int: %w", err)
			}
			logConfig.Collector = append(logConfig.Collector, LogCollector{
				IP:   log.Host,
				Port: port,
			})
		}
	}
	data, err := json.Marshal(logConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal log config: %w", err)
	}

	logger.GetLogger().Info("sending log config to dp-app", "config", string(data))

	// Sending log configuration to the accelerated dataplane
	msg := &socket.ControlMessage{
		Command: Dataplane_LogConfig,
		Type:    socket.DATAPLANE,
		Data:    data,
	}
	dpsocket := socket.NewDataplaneSocket(dp.ApiPath, UDS_TIMEOUT*time.Second)
	err = dpsocket.Connect()
	if err != nil {
		return err
	}
	defer dpsocket.Close()
	err = dpsocket.Send(msg)
	if err != nil {
		return err
	}
	rc, err := dpsocket.Receive()
	if err != nil {
		return err
	}
	if rc.ReturnCode < socket.SUCCESS {
		return errors.New(rc.ReturnCode.String())
	}
	return nil
}

// -----------------------------------------------------------------------------
// Accelerated Dataplane Implementation
// -----------------------------------------------------------------------------

type AcceleratedDataplane struct {
	Accelerated *AcceleratedDataplaneProcess
}

func (dp *AcceleratedDataplane) Type() DataplaneType {
	return ACCELERATED_DP
}

func (dp *AcceleratedDataplane) Version() string {
	return dp.Accelerated.Version
}

func (dp *AcceleratedDataplane) ApiPath() string {
	return dp.Accelerated.ApiPath
}

func (dp *AcceleratedDataplane) HardwareModel() string {
	return dp.Accelerated.Asic
}

func (dp *AcceleratedDataplane) PushPolicy(ctx context.Context, fwop v1alpha.PolicyOperation, policies []*switchpolicy.DPUPolicyRule) error {
	fwPolicy := dpAppPolicy.DPURuleToJSON(fwop, policies)

	// Creating policy message
	policyMsg := &dpAppPolicy.FwPolicyMsgV2{
		Hash:         "deprecated",
		Verification: false,
		Policies:     fwPolicy,
	}

	// Applying policy to the accelerated dataplane
	err := dp.Accelerated.UpdateFirewallPolicies(ctx, policyMsg)
	if err != nil {
		logger.GetLogger().Error("Failed to push policy to accelerated dataplane", logfields.Error, err, "policy", fwPolicy)
		return err
	}
	logger.GetLogger().Info("policy update", "policy", fwPolicy)
	return nil
}

func (dp *AcceleratedDataplane) ClearPolicy(ctx context.Context) error {
	// Applying policy to the accelerated dataplane
	err := dp.Accelerated.ClearFirewallPolicies(ctx)
	if err != nil {
		logger.GetLogger().Error("Failed to clear policy from accelerated dataplane", logfields.Error, err)
		return err
	}
	logger.GetLogger().Info("policy cleared")
	return nil
}

func (dp *AcceleratedDataplane) RefreshConfig(oldCfg *v1alpha.ConfigObject, newCfg *v1alpha.ConfigObject) error {
	// Checking config object
	cfg := newCfg
	if newCfg == nil {
		cfg = oldCfg
	}
	if cfg == nil {
		return errors.New("nil config object in dataplane config callback")
	}

	switch cfg.Type {
	case v1alpha.ConfigType_CONFIG_TYPE_DPU:
		// Parsing out the dpu configuration
		dpuConfig := cfg.GetConfigDpu()

		// Getting all IPv4 IPs on the exporter interface (there should only be 1, but if there are
		// more we only use the first) and flushing all of the IPs that are on the interface.
		link, err := netlink.LinkByName(EXPORTER_INTERFACE)
		if err != nil {
			return fmt.Errorf("failed to get %s interface: %w", EXPORTER_INTERFACE, err)
		}
		addrsV4, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			return fmt.Errorf("failed to list IPv4 addresses on %s: %w", EXPORTER_INTERFACE, err)
		}
		var intIP net.IP
		for _, a := range addrsV4 {
			if a.IPNet != nil && a.IP != nil {
				ip := a.IP.To4()
				if ip != nil {
					intIP = ip
				}
			}
			err := netlink.AddrDel(link, &a)
			if err != nil {
				return fmt.Errorf("failed to delete IPv4 address %s from %s: %w", a.String(), EXPORTER_INTERFACE, err)
			}
		}

		// Checking that an interface IP was found
		if intIP == nil {
			return errors.New("failed to get exporter interface IP")
		}

		// Adding the relevant IP address back to the exporter interface
		addr32, err := netlink.ParseAddr(intIP.String() + "/32")
		if err != nil {
			return fmt.Errorf("failed to parse address %s/32: %w", intIP.String(), err)
		}
		if err := netlink.AddrAdd(link, addr32); err != nil {
			return fmt.Errorf("failed to add %s IP %s to %s: %w", EXPORTER_INTERFACE, intIP.String(), EXPORTER_INTERFACE, err)
		}

		// Setting the source port range that is reserved for log export
		portRangeContent := fmt.Sprintf("%d   %d\n", dpuConfig.PortLow, dpuConfig.PortLow+LOGGER_PORT_COUNT)
		err = os.WriteFile("/proc/sys/net/ipv4/ip_local_port_range", []byte(portRangeContent), 0644)
		if err != nil {
			return fmt.Errorf("failed to set port range: %w", err)
		}

		// Setting NPU IP and MAC
		dp.Accelerated.NpuIp = dpuConfig.ServiceIp
		dp.Accelerated.NpuMac = dpuConfig.ServiceMac
		logger.GetLogger().Error("dpu config", "npuIp", dpuConfig.ServiceIp, "npuMac", dpuConfig.ServiceMac)
		err = dp.Accelerated.SendDpuConfig(dpuConfig)
		if err != nil {
			return err
		}
		return nil
	case v1alpha.ConfigType_CONFIG_TYPE_LOG_SYSLOG, v1alpha.ConfigType_CONFIG_TYPE_LOG_IPFIX, v1alpha.ConfigType_CONFIG_TYPE_LOG_TIMESCAPE, v1alpha.ConfigType_CONFIG_TYPE_LOG_SPLUNK:
		// Switching on config type
		var logConfigs map[string]*v1alpha.LogConfig
		switch cfg.Type {
		case v1alpha.ConfigType_CONFIG_TYPE_LOG_SYSLOG:
			logConfigs = cfg.GetConfigLogSyslog().Configs
		case v1alpha.ConfigType_CONFIG_TYPE_LOG_IPFIX:
			logConfigs = cfg.GetConfigLogIpfix().Configs
		case v1alpha.ConfigType_CONFIG_TYPE_LOG_TIMESCAPE:
			logConfigs = cfg.GetConfigLogTimescape().Configs
		case v1alpha.ConfigType_CONFIG_TYPE_LOG_SPLUNK:
			logConfigs = cfg.GetConfigLogSplunk().Configs
		}

		// Checking for deletion
		if newCfg == nil {
			logConfigs = make(map[string]*v1alpha.LogConfig)
		}

		// Sending log config update message to dataplane
		err := dp.Accelerated.SendLogConfig(logConfigs)
		if err != nil {
			return err
		}
		return nil
	default:
		return errors.New("invalid config type")
	}
}

func (dp *AcceleratedDataplane) Init(ctx context.Context) error {
	err := dp.Accelerated.Init(ctx)
	if err != nil {
		return err
	}
	return nil
}

func (dp *AcceleratedDataplane) Connect(ctx context.Context) error {
	// Initializing dataplane
	err := dp.Init(ctx)
	if err != nil {
		return err
	}

	// Starting the dataplane
	ctxTimeout, cancel := context.WithTimeout(ctx, TIMEOUT*time.Second)
	defer cancel()
	err = dp.Start(ctxTimeout)
	if err != nil {
		return err
	}
	return nil
}

func (dp *AcceleratedDataplane) Close(ctx context.Context) {
	dp.Stop(ctx)
}

func (dp *AcceleratedDataplane) Start(ctx context.Context) error {
	// Extracting logger from context
	// Starting accelerated dataplane
	err := dp.Accelerated.Start(ctx)
	if err != nil {
		logger.GetLogger().Error("Failed to start accelerated dataplane", logfields.Error, err)
		return err
	}

	return nil
}

func (dp *AcceleratedDataplane) Stop(ctx context.Context) error {
	// Stopping accelerated dataplane
	err := dp.Accelerated.Stop(ctx)
	if err != nil {
		logger.GetLogger().Error("Failed to stop accelerated dataplane", logfields.Error, err)
		return err
	}

	return nil
}

func (dp *AcceleratedDataplane) Restart(ctx context.Context) error {
	// Stopping and starting dataplane
	err := dp.Stop(ctx)
	if err != nil {
		logger.GetLogger().Error("Failed to restart dataplane", logfields.Error, err)
		return err
	}
	err = dp.Start(ctx)
	if err != nil {
		logger.GetLogger().Error("Failed to restart dataplane", logfields.Error, err)
		return err
	}
	return nil
}

func (dp *AcceleratedDataplane) Status() bool {
	// Returning status of the accelerated dataplane
	return dp.Accelerated.Status.Load()
}

// -----------------------------------------------------------------------------
// Helper Functions
// -----------------------------------------------------------------------------

// Runs the command and returns the combined stdout and stderr output
func runCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s: %s", err, string(output))
	}
	return string(output), nil
}
