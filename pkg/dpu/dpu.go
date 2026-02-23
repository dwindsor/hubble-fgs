// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package dpu

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/version"

	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"

	"github.com/isovalent/hubble-fgs/pkg/config"
	"github.com/isovalent/hubble-fgs/pkg/config/library"
	"github.com/isovalent/hubble-fgs/pkg/dpu/dataplane"
	"github.com/isovalent/hubble-fgs/pkg/dpu/events"
	"github.com/isovalent/hubble-fgs/pkg/dpu/exporter"
	"github.com/isovalent/hubble-fgs/pkg/dpu/policy"
	"github.com/isovalent/hubble-fgs/pkg/model/switchpolicy"
	"github.com/isovalent/hubble-fgs/pkg/utils"
	"github.com/isovalent/hubble-fgs/pkg/utils/smartqueue"
)

const (
	BUFSIZE = 4096

	// on firewall.*, use ens5. on real dpu, int_mnic0
	DPU_INTERFACE = "int_mnic0"

	// chosen to be 30 seconds, this value needs to be sufficiently large
	// because it blocks updates from AGW while running the Checksum. As
	// the value gets larger it can significantly delay policy update when
	// set to small values, such as 1 second.
	KEEPALIVE_INTERVAL    = 30 * time.Second
	MAX_KEEPALIVE_BACKOFF = 120 * time.Second

	EXPORTER_CONFIG_PATH    = "/data/hypershield/daflogger.yaml" // HACK: need to update config to pass this path
	EVENTLOGGER_SOCKET_PATH = "/tmp/fluentbit_fwa.sock"          // HACK: need to pass through config

	STALE_POLICY_GC       = 120
	STALE_POLICY_GC_RETRY = 3

	IPC_EVENT_SOCKET_PATH = "/tmp/fwa_ha_events.sock"
)

type StreamClient struct {
	client       v1alpha.L3L4NetworkPolicyServiceClient
	ctx          context.Context
	conn         *grpc.ClientConn
	policyStream grpc.ServerStreamingClient[v1alpha.Streaml3L4NetworkPolicyResponse]
	configStream grpc.ServerStreamingClient[v1alpha.StreamDatapathConfigResponse]
}

type ruleTracker struct {
	timestamp time.Time
	shaMap    map[[sha256.Size]byte]struct{}
}

func NewDPUAgent(server string) *DPUAgent {
	return &DPUAgent{
		Cfg:          &config.Config{},
		EventLogger:  &events.EventLogger{},
		Retries:      5,
		streamClient: &StreamClient{},
		// This uses the sha of the PolicyRule as the key. The value though is
		// the message. We SHA256 the rule so that the operation matches for
		// both UPSERT and DELETE. To get a Set sha256 we can take the sha256
		// of the concatenated strings in this map.
		ruleSet:       make(map[string]*ruleTracker),
		serverAddress: server,
		ruleSetLock:   sync.RWMutex{},
	}
}

type DPUAgent struct {
	AgentId      string
	TenantId     string
	Name         string
	Ip           string
	Hostname     string
	Architecture string
	Os           string

	serverAddress string

	ReadyStatus      atomic.Bool
	ConnectionStatus atomic.Bool

	Dataplane         dataplane.Dataplane
	LogExporter       exporter.Exporter
	EnableEventStream bool

	EventLogger    *events.EventLogger
	SyslogHostname string
	SyslogAppname  string

	Cfg          *config.Config
	Retries      int
	streamClient *StreamClient
	eventQueue   *smartqueue.SmartQueue[*v1alpha.StreamEvent]
	// This uses the sha of the PolicyRule as the key. The value though is
	// the message. We SHA256 the rule so that the operation matches for
	// both UPSERT and DELETE. To get a Set sha256 we can take the sha256
	// of the concatenated strings in this map.
	ruleSet      map[string]*ruleTracker
	ruleSetLock  sync.RWMutex
	DpuReboot    uint32
	DpuBootTime  time.Time
	DpCrash      uint32
	LastDpCrash  time.Time
	LastFwaCrash time.Time
}

func (dpu *DPUAgent) Id() string {
	return dpu.AgentId
}

func (dpu *DPUAgent) Tenant() string {
	return dpu.TenantId
}

func (dpu *DPUAgent) Version() string {
	return version.Version
}

func ReadUintFromFile(path string) (uint32, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	trimmed := strings.TrimSpace(string(data))
	val, err := strconv.ParseUint(trimmed, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("failed to parse reboot count from %s: %w", path, err)
	}
	return uint32(val), nil
}

// This returns the modification time of a file
func GetFileModifiedTime(path string) (time.Time, error) {
	info, err := os.Stat(path)
	if err != nil {
		return time.Time{}, err
	}
	return info.ModTime(), nil
}

// Extract bootcount and last time of core file creation
// Format: core_<bootcount>__pds_dp_app_pds_dp_app_*.tar
func (dpu *DPUAgent) checkForCoreDump() {

	dpu.DpCrash = 0
	dpu.LastDpCrash = time.Time{}
	// Most recent core dump file created
	cmd := exec.Command("sh", "-c", "ls -t /data/core/core_*__pds_dp_app_pds_dp_app_*.tar 2>/dev/null | head -n 1")
	output, err := cmd.Output()
	if err != nil || len(output) == 0 {
		logger.GetLogger().Debug("No core dump files found")
		return
	}

	filePath := strings.TrimSpace(string(output))

	// Extract bootcount: core_<bootcount>__pds_dp_app_pds_dp_app_*.tar
	re := regexp.MustCompile(`core_(\d+)__pds_dp_app_pds_dp_app_.*\.tar$`)
	matches := re.FindStringSubmatch(filePath)
	if len(matches) < 2 {
		logger.GetLogger().Error("Failed to extract bootcount from filename", "file", filePath)
		return
	}

	crashCount, err := strconv.ParseUint(matches[1], 10, 32)
	if err != nil {
		logger.GetLogger().Error("Failed to parse bootcount", "bootcount", matches[1], logfields.Error, err)
		return
	}

	fileInfo, err := os.Stat(filePath)
	if err != nil {
		logger.GetLogger().Error("Failed to find time core dump file was created", logfields.Error, err, "file", filePath)
		return
	}

	// Update DPU crash info
	dpu.DpCrash = uint32(crashCount)
	dpu.LastDpCrash = fileInfo.ModTime()
}

// Extract last time of FWA crash file creation
// Format: core_<bootcount>__fwa_fwa_*.tar
func (dpu *DPUAgent) checkForFwaCrash() {

	dpu.LastFwaCrash = time.Time{}
	// Most recent FWA crash file created
	cmd := exec.Command("sh", "-c", "ls -t /data/core/core_*__fwa_fwa_*.tar 2>/dev/null | head -n 1")
	output, err := cmd.Output()
	if err != nil || len(output) == 0 {
		logger.GetLogger().Debug("No FWA crash files found")
		return
	}

	filePath := strings.TrimSpace(string(output))
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		logger.GetLogger().Error("Failed to find time FWA crash file was created", logfields.Error, err, "file", filePath)
		return
	}
	// Update FWA crash time info
	dpu.LastFwaCrash = fileInfo.ModTime()
}

func (dpu *DPUAgent) updateDpuRebootCrashInfo() {
	bootCount, err := ReadUintFromFile("/obfl/boot_count.txt")
	if err != nil {
		logger.GetLogger().Error("Failed to read /obfl/boot_count.txt", logfields.Error, err)
		return
	}

	// get the last boot time from the /obfl/boot_count.txt file
	lastBootTime, err := GetFileModifiedTime("/obfl/boot_count.txt")
	if err != nil {
		logger.GetLogger().Error("Failed to get the modified time of /obfl/boot_count.txt", logfields.Error, err)
		return
	}
	// Update the number of boots and last time of boot
	dpu.DpuReboot = bootCount
	dpu.DpuBootTime = lastBootTime
	//Update the core info
	dpu.checkForCoreDump()
	//Update the FWA crash info
	dpu.checkForFwaCrash()
}

func (dpu *DPUAgent) Config(ctx context.Context, configPath string, dpSocketPath string, enableDataplane bool, enableLogger bool, enableEventStream bool) error {
	// Extracting logger and agent from context
	// Collecting agent metadata
	var err error

	dpu.Hostname, err = os.Hostname()
	if err != nil {
		logger.GetLogger().Error("failed to get machine hostname", logfields.Error, err)
	}
	dpu.Architecture = runtime.GOARCH
	dpu.Os = runtime.GOOS

	// Setting up config
	created, err := dpu.Cfg.Init(configPath)
	if err != nil {
		logger.GetLogger().Error("Failed to initialize config", logfields.Error, err)
		return err
	}
	if created {
		logger.GetLogger().Info("Config file not found, new config file created with default values", "logfile", configPath)
	}

	if enableDataplane {
		dpu.Dataplane = dataplane.NewAcceleratedDataplane("dp-app", dpSocketPath)
	} else {
		dpu.Dataplane = dataplane.NewMockDataplane()
	}

	logger.GetLogger().Info("configure DPU", "host", dpu.Hostname, "OS", dpu.Os, "Arch", dpu.Architecture)

	// Get DPU IP with retry - w/o a valid AgentId, the DPU cannot register with AGW
	// GetDpuIP will retry with exponential backoff (.5s -> 5s max) for up to 30 seconds
	// and respects context cancellation for graceful shutdown
	dpuIp, err := utils.GetDpuIP(ctx, DPU_INTERFACE)
	if err != nil {
		logger.GetLogger().Error("Fail to get DPU IP, setting to 127.0.0.1", logfields.Error, err)
		dpuIp = "127.0.0.1"
	}
	dpu.AgentId = dpuIp
	dpu.Ip = dpuIp
	logger.GetLogger().Info("Using DPU IP as AgentId", "id", dpu.AgentId)

	// Setting up log exporter and event logger
	if enableLogger {
		dpu.LogExporter = exporter.NewAcceleratedFluentbitExporter("", EXPORTER_CONFIG_PATH)
		dpu.EventLogger = events.NewEventLogger(EVENTLOGGER_SOCKET_PATH)
	} else {
		dpu.LogExporter = exporter.NewMockExporter()
	}

	// update dpu reboot and crash info
	dpu.updateDpuRebootCrashInfo()

	// Store event stream setting
	dpu.EnableEventStream = enableEventStream

	return nil
}

func (dpu *DPUAgent) Setup(ctx context.Context) error {
	logger.GetLogger().Info("Setup Accelerated Dataplane")

	// Setting up dataplane
	err := dpu.Dataplane.Connect(ctx)
	if err != nil {
		logger.GetLogger().Error("failed to setup dataplane connection",
			logfields.Error, err)
		return err
	}
	logger.GetLogger().Info("Connected to dataplane", "type", dpu.Dataplane.Type(), "version", dpu.Dataplane.Version(), "hardware", dpu.Dataplane.HardwareModel())

	// Clearing all dataplane policies on startup
	err = dpu.Dataplane.ClearPolicy(ctx)
	if err != nil {
		logger.GetLogger().Error("failed to clear dataplane policies", logfields.Error, err)
		return err
	}
	logger.GetLogger().Info("Cleared all dataplane policies")

	// Setting up exporter
	err = dpu.LogExporter.Init(ctx)
	if err != nil {
		logger.GetLogger().Error("failed to initialize logger, continue without log exporter", logfields.Error, err)
	}

	// Creating custom callback functions
	logConfigCallback := func(oldCfg *v1alpha.ConfigObject, newCfg *v1alpha.ConfigObject) error {
		err := dpu.LogExporter.RefreshConfig(oldCfg, newCfg)
		if err != nil {
			logger.GetLogger().Error("log config failed", "callback", "log-exporter", logfields.Error, err)
			return err
		}
		err = dpu.Dataplane.RefreshConfig(oldCfg, newCfg)
		if err != nil {
			logger.GetLogger().Error("log config failed", "callback", "dataplane", logfields.Error, err)
			return err
		}
		return nil
	}
	dpuConfigCallback := func(oldCfg *v1alpha.ConfigObject, newCfg *v1alpha.ConfigObject) error {
		err := dpu.Dataplane.RefreshConfig(oldCfg, newCfg)
		if err != nil {
			logger.GetLogger().Error("dpu config failed", "callback", "dataplane", logfields.Error, err)
			return err
		}
		err = dpu.LogExporter.RefreshConfig(oldCfg, newCfg)
		if err != nil {
			logger.GetLogger().Error("dpu config failed", "callback", "log-exporter", logfields.Error, err)
			return err
		}
		return nil
	}
	haConfigCallback := func(oldCfg *v1alpha.ConfigObject, newCfg *v1alpha.ConfigObject) error {
		err := dpu.Dataplane.RefreshConfig(oldCfg, newCfg)
		if err != nil {
			logger.GetLogger().Error("ha config failed", "callback", "dataplane", logfields.Error, err)
			return err
		}
		return nil
	}

	networkConfigCallback := func(oldCfg *v1alpha.ConfigObject, newCfg *v1alpha.ConfigObject) error {
		err := dpu.Dataplane.RefreshConfig(oldCfg, newCfg)
		if err != nil {
			logger.GetLogger().Error("network config failed", "callback", "dataplane", logfields.Error, err)
			return err
		}
		return nil
	}

	// Adding config callbacks
	library.GetRepository().AddConfigCallback(v1alpha.ConfigType_CONFIG_TYPE_DPU, dpuConfigCallback)
	library.GetRepository().AddConfigCallback(v1alpha.ConfigType_CONFIG_TYPE_LOG_SYSLOG, logConfigCallback)
	library.GetRepository().AddConfigCallback(v1alpha.ConfigType_CONFIG_TYPE_LOG_IPFIX, logConfigCallback)
	library.GetRepository().AddConfigCallback(v1alpha.ConfigType_CONFIG_TYPE_LOG_TIMESCAPE, logConfigCallback)
	library.GetRepository().AddConfigCallback(v1alpha.ConfigType_CONFIG_TYPE_HA, haConfigCallback)
	library.GetRepository().AddConfigCallback(v1alpha.ConfigType_CONFIG_TYPE_NETWORK, networkConfigCallback)

	return nil
}

func (dpu *DPUAgent) Close(ctx context.Context) error {
	dpu.Dataplane.Close(ctx)
	if dpu.LogExporter != nil {
		dpu.LogExporter.Close(ctx)
	}
	dpu.EventLogger.Close()
	return nil
}

func (dpu *DPUAgent) Ready(_ context.Context) error {
	// Setting agent ready
	dpu.ReadyStatus.Store(true)
	return nil
}

// This abstraction is a bit broken we need a ruleSet object
// that we can do work over to share code between client and
// server agents. Will do after initial merge.
func (dpu *DPUAgent) Checksum() [sha256.Size]byte {
	dpu.ruleSetLock.RLock()
	defer dpu.ruleSetLock.RUnlock()

	keys := make([][]byte, 0, len(dpu.ruleSet))

	for _, r := range dpu.ruleSet {
		for sha := range r.shaMap {
			keys = append(keys, sha[:])
		}
	}
	sort.Slice(keys, func(x, y int) bool {
		return bytes.Compare(keys[x], keys[y]) <= 0
	})
	sep := []byte(":")
	joinedRules := bytes.Join(keys, sep)
	return sha256.Sum256([]byte(joinedRules))

}

func (dpu *DPUAgent) upsertPolicyRule(rule *switchpolicy.DPUPolicyRule) error {
	dpu.ruleSetLock.Lock()
	defer dpu.ruleSetLock.Unlock()

	uid := policy.RuleToID(rule.Policy)
	csum, err := switchpolicy.HashRule(rule.Policy)
	if err != nil {
		logger.GetLogger().Error("Failed policy rule checksum, corrupted policy",
			logfields.Error, err, "rule", rule)
		return fmt.Errorf("failed policy rule checksum, corrupted policy")
	}

	if rule, ok := dpu.ruleSet[uid]; ok {
		rule.timestamp = time.Now()
		rule.shaMap[csum] = struct{}{}
		return nil
	}

	ruleTracker := &ruleTracker{
		timestamp: time.Now(),
		shaMap:    make(map[[sha256.Size]byte]struct{}),
	}
	ruleTracker.shaMap[csum] = struct{}{}
	dpu.ruleSet[uid] = ruleTracker
	return nil
}

func (dpu *DPUAgent) deletePolicyRule(rule *switchpolicy.DPUPolicyRule) error {
	dpu.ruleSetLock.Lock()
	defer dpu.ruleSetLock.Unlock()

	uid := policy.RuleToID(rule.Policy)
	if _, ok := dpu.ruleSet[uid]; !ok {
		return fmt.Errorf("policy does not exists")
	}
	delete(dpu.ruleSet, uid)
	return nil
}

func (dpu *DPUAgent) PolicyEventLoop(ctx context.Context) error {
	logger.GetLogger().Info("policy event loop")
	for {
		resp, err := dpu.streamClient.policyStream.Recv()
		if err == io.EOF {
			return err
		}
		if err != nil {
			return err
		}

		rule := switchpolicy.ResponseToDPURule(resp)
		policyList := []*switchpolicy.DPUPolicyRule{rule}

		switch resp.Oper {
		case v1alpha.PolicyOperation_POLICY_OPERATION_UNSPECIFIED:
			logger.GetLogger().Error("failed policy, unknown operation")
		case v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT:
			dpu.ruleSetLock.Lock()
			err = dpu.Dataplane.PushPolicy(ctx, v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT, policyList)
			dpu.ruleSetLock.Unlock()
			if err != nil {
				logger.GetLogger().Error("upsert failed", logfields.Error, err)
				dpu.queuePolicyRuleEvent(ctx, rule, false, v1alpha.PolicyRuleError_POLICY_RULE_ERROR_UNSPECIFIED, err.Error())
				continue
			}

			// Queue success event to stream
			dpu.queuePolicyRuleEvent(ctx, rule, true, v1alpha.PolicyRuleError_POLICY_RULE_ERROR_UNSPECIFIED, "")

			err := dpu.upsertPolicyRule(rule)
			if err != nil {
				logger.GetLogger().Error("failed to upsert rule", logfields.Error, err)
				continue
			}

			// Log event
			msg := events.NewEventLogMessage(events.MSGCODE_POLICY)
			msg.PolicyOperation = "upsert"
			msg.PolicyId = rule.Policy.PolicyName
			dpu.EventLogger.Log(msg)
		case v1alpha.PolicyOperation_POLICY_OPERATION_DELETE:
			dpu.ruleSetLock.Lock()
			err = dpu.Dataplane.PushPolicy(ctx, v1alpha.PolicyOperation_POLICY_OPERATION_DELETE, policyList)
			dpu.ruleSetLock.Unlock()
			if err != nil {
				logger.GetLogger().Error("delete failed", logfields.Error, err)
				dpu.queuePolicyRuleEvent(ctx, rule, false, v1alpha.PolicyRuleError_POLICY_RULE_ERROR_UNSPECIFIED, err.Error())
				continue
			}
			err := dpu.deletePolicyRule(rule)
			if err != nil {
				logger.GetLogger().Error("failed to delete rule", logfields.Error, err)
				continue
			}

			// Queue success event to stream
			dpu.queuePolicyRuleEvent(ctx, rule, true, v1alpha.PolicyRuleError_POLICY_RULE_ERROR_UNSPECIFIED, "")

			// Log event
			msg := events.NewEventLogMessage(events.MSGCODE_POLICY)
			msg.PolicyOperation = "delete"
			msg.PolicyId = rule.Policy.PolicyName
			dpu.EventLogger.Log(msg)
		}

	}
}

func (dpu *DPUAgent) ConfigEventLoop(_ context.Context) error {
	logger.GetLogger().Info("config event loop")
	for {
		resp, err := dpu.streamClient.configStream.Recv()
		if err == io.EOF {
			return err
		}
		if err != nil {
			return err
		}

		switch resp.Oper {
		case v1alpha.ConfigOperation_CONFIG_OPERATION_UNSPECIFIED:
			logger.GetLogger().Error("failed config, unknown operation")
		case v1alpha.ConfigOperation_CONFIG_OPERATION_UPSERT:
			err = library.GetRepository().AddConfig(resp.Config)
			if err != nil {
				logger.GetLogger().Error("failed config, could not upsert", logfields.Error, err)
				continue
			}
			logger.GetLogger().Info("upserted config", "config", resp.Config) // FIXME: remove sensitive fields

			// Log event
			msg := events.NewEventLogMessage(events.MSGCODE_CONFIG)
			msg.ConfigOperation = "upsert"
			msg.ConfigType = resp.Config.Type.String()
			dpu.EventLogger.Log(msg)
		case v1alpha.ConfigOperation_CONFIG_OPERATION_DELETE:
			err = library.GetRepository().DeleteConfig(v1alpha.ConfigType(resp.Config.Type))
			if err != nil {
				logger.GetLogger().Error("failed config, could not delete", logfields.Error, err)
				continue
			}
			logger.GetLogger().Info("deleted config", "config", resp.Config) // FIXME: remove sensitive fields

			// Log event
			msg := events.NewEventLogMessage(events.MSGCODE_CONFIG)
			msg.ConfigOperation = "delete"
			msg.ConfigType = resp.Config.Type.String()
			dpu.EventLogger.Log(msg)
		}
	}
}

// getPortRange retrieves the port range from DPU config in repository
func (dpu *DPUAgent) getPortRange() (uint32, uint32) {
	var dpuConfig v1alpha.DpuConfig
	err := library.GetRepository().GetConfig(v1alpha.ConfigType_CONFIG_TYPE_DPU, &dpuConfig)
	if err != nil && !library.IsConfigNotFound(err) {
		logger.GetLogger().Error("get dpu config", logfields.Error, err)
		return 0, 0
	}
	if dpuConfig.PortLow != 0 && dpuConfig.PortHigh != 0 {
		// Use values from repository config
		return dpuConfig.PortLow, dpuConfig.PortHigh
	}
	// Error or Repository config exists but ports not set, use local config
	logger.GetLogger().Debug("Repository config exists but ports not set, using local config", "portLow", 0, "portHigh", 0)
	return 0, 0
}

func (dpu *DPUAgent) KeepAlive(ctx context.Context) error {
	backoff := KEEPALIVE_INTERVAL
	attempts := 0
	for {
		select {
		case <-ctx.Done():
			logger.GetLogger().Info("Stopping keep-alive")
			return nil
		case <-time.After(backoff):
			csum := dpu.Checksum()

			// getPortRange retrieves the port range from DPU config in repository
			portLow, portHigh := dpu.getPortRange()

			status := &v1alpha.ReportStatus{
				AgentUid:             dpu.AgentId,
				DpVersion:            dpu.Dataplane.Version(),
				AgentVersion:         dpu.Version(),
				PolicyChecksum:       hex.EncodeToString(csum[:]),
				Hostname:             dpu.Hostname,
				Architecture:         dpu.Architecture,
				Os:                   dpu.Os,
				Type:                 v1alpha.AgentType_AGENT_TYPE_DPU_AGW,
				SerialNumber:         "serialNumber",
				HardwareModel:        dpu.Dataplane.HardwareModel(),
				DpuRestarts:          dpu.DpuReboot,
				LastDpuRestart:       timestamppb.New(dpu.DpuBootTime),
				DataplaneRestarts:    dpu.DpCrash,
				LastDataplaneRestart: timestamppb.New(dpu.LastDpCrash),
				LastFwaCrashTime:     timestamppb.New(dpu.LastFwaCrash),
				PortLow:              portLow,
				PortHigh:             portHigh,
			}

			req := &v1alpha.ReportStatusRequest{
				Status: status,
			}
			//FWA calls this function to send keep alive report stats to AGW
			_, err := dpu.streamClient.client.ReportStatus(ctx, req)
			if err != nil {
				attempts++
				logger.GetLogger().Error("Keepalive connection attempt failed, retrying...", "server-address", dpu.serverAddress, "attempts", attempts, "backoff", backoff, "error", err)
				if attempts < dpu.Retries {
					backoff *= 2
				}
				continue
			}
			attempts = 0
			backoff = time.Second
		}
	}
}

func (dpu *DPUAgent) stalePolicyGC(ctx context.Context, invokeTime time.Time) {
	delUIDs := []string{}

	dpu.ruleSetLock.Lock()
	for uid, tracker := range dpu.ruleSet {
		if tracker.timestamp.Before(invokeTime) {
			delete(dpu.ruleSet, uid)
			delUIDs = append(delUIDs, uid)
		}
	}
	dpu.ruleSetLock.Unlock()

	ev := policy.EndpointV2{
		Ip:    "0.0.0.0/32",
		Ports: []policy.PortV2{},
		Vlan:  0,
		Vrf:   0,
	}

	delList := []policy.FwPolicyV2{}
	for _, uid := range delUIDs {
		fwp := policy.FwPolicyV2{
			Id:          uid,
			Name:        uid,
			Operation:   1, //delete op
			Effect:      "",
			Source:      ev,
			Destination: ev,
		}
		delList = append(delList, fwp)
	}

	// We need to keep the lock to avoid racing with someone readding
	// an identical policy that we would then delete.
	for i := 0; i < STALE_POLICY_GC_RETRY; i++ {
		dpu.ruleSetLock.Lock()
		err := dpu.Dataplane.PushFwPolicy(ctx, delList)
		dpu.ruleSetLock.Unlock()
		if err != nil {
			logger.GetLogger().Error("Failed to remove stale policy", "attempt", i)
		} else {
			break
		}
		time.Sleep(1 * time.Second)
	}
}

func (dpu *DPUAgent) PolicyConnect(ctx context.Context) error {
	policyReq := &v1alpha.Streaml3L4NetworkPolicyRequest{
		AgentUid: dpu.AgentId,
	}

	backoff := time.Second
	attempts := 0
	for {
		select {
		case <-ctx.Done():
			logger.GetLogger().Info("Policy client connection closed")
			return nil
		case <-time.After(backoff):
			logger.GetLogger().Info("Connecting policy client...")
			var err error
			dpu.streamClient.policyStream, err = dpu.streamClient.client.Streaml3L4NetworkPolicy(ctx, policyReq)
			if err != nil {
				attempts++
				logger.GetLogger().Error("Policy stream connection attempt failed, retrying...", "server-address", dpu.serverAddress, "attempts", attempts, "backoff", backoff, "error", err)
				if attempts < dpu.Retries {
					backoff *= 2
				}
				continue
			}
			logger.GetLogger().Info("Policy client connected.")

			attempts = 0
			backoff = time.Second

			delayDuration := STALE_POLICY_GC * time.Second
			invokeTime := time.Now()
			timer := time.AfterFunc(delayDuration, func() {
				dpu.stalePolicyGC(ctx, invokeTime)
			})

			logger.GetLogger().Info("Network Policy listening...")
			if err := dpu.PolicyEventLoop(ctx); err != nil {
				logger.GetLogger().Error("policy event loop aborted", logfields.Error, err)
			}
			timer.Stop()
		}
	}
}

func (dpu *DPUAgent) ConfigConnect(ctx context.Context) error {
	configReq := &v1alpha.StreamDatapathConfigRequest{
		AgentUid: dpu.AgentId,
	}

	backoff := time.Second
	attempts := 0
	for {
		select {
		case <-ctx.Done():
			logger.GetLogger().Info("Config client connection closed")
			return nil
		case <-time.After(backoff):
			logger.GetLogger().Info("Connecting config client...")
			var err error
			dpu.streamClient.configStream, err = dpu.streamClient.client.StreamDatapathConfig(ctx, configReq)
			if err != nil {
				attempts++
				logger.GetLogger().Error("Config stream connection attempt failed, retrying...", "server-address", dpu.serverAddress, "attempts", attempts, "backoff", backoff, "error", err)
				if attempts < dpu.Retries {
					backoff *= 2
				}
				continue
			}
			logger.GetLogger().Info("Config client connected.")

			attempts = 0
			backoff = time.Second

			logger.GetLogger().Info("Config listening...")
			if err := dpu.ConfigEventLoop(ctx); err != nil {
				logger.GetLogger().Error("config event loop aborted", logfields.Error, err)
			}
		}
	}
}

func (dpu *DPUAgent) queuePolicyRuleEvent(ctx context.Context, rule *switchpolicy.DPUPolicyRule, isSuccess bool, errorType v1alpha.PolicyRuleError, errorMsg string) {
	if dpu.eventQueue == nil {
		return
	}

	event := &v1alpha.StreamEvent{
		AgentUid:  dpu.AgentId,
		Timestamp: timestamppb.Now(),
		Event: &v1alpha.StreamEvent_Rule{
			Rule: &v1alpha.PolicyRuleEvent{
				RuleName:           rule.Policy.RuleName,
				PolicyName:         rule.Policy.PolicyName,
				K8SUid:             rule.Policy.K8SUid,
				K8SResourceVersion: rule.Policy.K8SResourceVersion,
				IsSuccess:          isSuccess,
				Error:              errorType,
				ErrorMessage:       errorMsg,
			},
		},
	}

	if !dpu.eventQueue.Enqueue(ctx, event) {
		logger.GetLogger().Warn("Failed to enqueue policy rule event, queue full or stopped",
			"policyName", rule.Policy.PolicyName,
			"ruleName", rule.Policy.RuleName)
	}
}

func (dpu *DPUAgent) IPCEventListener(ctx context.Context) error {
	socketPath := IPC_EVENT_SOCKET_PATH

	if err := os.RemoveAll(socketPath); err != nil {
		logger.GetLogger().Error("Failed to remove existing IPC socket", logfields.Error, err)
		return err
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		logger.GetLogger().Error("Failed to create IPC unix socket listener", logfields.Error, err)
		return err
	}
	defer listener.Close()
	defer os.RemoveAll(socketPath)

	logger.GetLogger().Info("IPC event listener started", "socket", socketPath)

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				logger.GetLogger().Info("IPC event listener shutting down")
				return nil
			default:
				logger.GetLogger().Error("Failed to accept IPC connection", logfields.Error, err)
				continue
			}
		}

		go dpu.handleIPCConnection(ctx, conn)
	}
}

func (dpu *DPUAgent) handleIPCConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
		}

		msg := scanner.Bytes()
		if len(msg) == 0 {
			continue
		}

		event := &v1alpha.StreamEvent{}
		if err := protojson.Unmarshal(msg, event); err != nil {
			logger.GetLogger().Error("Failed to unmarshal IPC event JSON", logfields.Error, err, "message", string(msg))
			continue
		}

		// TODO: Remove log for performance
		logger.GetLogger().Info("received event message", "event", event)

		if dpu.eventQueue == nil {
			logger.GetLogger().Warn("Event queue not initialized, dropping IPC event", "event", event)
			continue
		}

		if !dpu.eventQueue.Enqueue(ctx, event) {
			logger.GetLogger().Error("Failed to enqueue IPC event, queue full or stopped", "event", event)
		}
	}

	if err := scanner.Err(); err != nil {
		select {
		case <-ctx.Done():
		default:
			logger.GetLogger().Error("Error reading from IPC connection", logfields.Error, err)
		}
	}
}

func (dpu *DPUAgent) EventConnect(ctx context.Context, ready chan struct{}) error {
	var stream grpc.ClientStreamingClient[v1alpha.StreamEventsRequest, v1alpha.StreamEventsResponse]
	var streamMu sync.Mutex

	openStream := func() error {
		if dpu.streamClient == nil || dpu.streamClient.client == nil {
			return fmt.Errorf("gRPC client not connected")
		}
		var err error
		stream, err = dpu.streamClient.client.StreamEvents(ctx)
		if err != nil {
			return fmt.Errorf("failed to open event stream: %w", err)
		}
		logger.GetLogger().Info("Event stream connected")
		return nil
	}

	// callback retries forever with exponential backoff to guarantee all queued
	// events are eventually sent. We never drop events - if the connection fails,
	// we keep reconnecting until the send succeeds or the context is cancelled.
	callback := func(ctx context.Context, events []*v1alpha.StreamEvent) {
		const maxBackoff = 15 * time.Second
		backoff := 100 * time.Millisecond

		for attempt := 1; ; attempt++ {
			var sendErr error

			// Try to send - lock only for the duration of stream access
			// Using function wrapper so we can use defer statement to guarantee unlock
			func() {
				streamMu.Lock()
				defer streamMu.Unlock()

				if stream == nil {
					if err := openStream(); err != nil {
						sendErr = fmt.Errorf("open stream: %w", err)
						return
					}
				}

				if err := stream.Send(&v1alpha.StreamEventsRequest{Events: events}); err != nil {
					stream = nil
					sendErr = fmt.Errorf("send: %w", err)
					return
				}
			}()

			if sendErr == nil {
				logger.GetLogger().Debug("Successfully sent events batch", "count", len(events))
				return
			}

			// Waiting with backoff or exit on context cancellation
			logger.GetLogger().Error("Failed to send events batch, retrying...", logfields.Error, sendErr, "count", len(events), "attempt", attempt, "backoff", backoff)
			select {
			case <-ctx.Done():
				logger.GetLogger().Info("Context cancelled, dropping events batch", "count", len(events))
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, maxBackoff)
		}
	}

	dpu.eventQueue = smartqueue.New(ctx, smartqueue.Config[*v1alpha.StreamEvent]{
		MaxSize:       256,
		BatchSize:     64,
		FlushInterval: 5 * time.Second,
		WorkerCount:   1,
		Callback:      callback,
	})

	dpu.eventQueue.Start()
	close(ready)
	logger.GetLogger().Info("Event queue started and ready")

	<-ctx.Done()
	dpu.eventQueue.Stop()

	streamMu.Lock()
	if stream != nil {
		stream.CloseAndRecv()
	}
	streamMu.Unlock()

	return nil
}

func (dpu *DPUAgent) Connect(ctx context.Context) error {
	var err error

	dpu.streamClient = &StreamClient{}

	logger.GetLogger().Info("Starting Streaming client")
	dpu.streamClient.conn, err = grpc.NewClient(
		dpu.serverAddress,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:    10 * time.Second,
			Timeout: 3 * time.Second,
		}),
	)
	if err != nil {
		logger.GetLogger().Error("GRPC client create error", logfields.Error, err)
		return err
	}

	dpu.streamClient.client = v1alpha.NewL3L4NetworkPolicyServiceClient(dpu.streamClient.conn)
	dpu.streamClient.ctx = ctx
	defer dpu.streamClient.conn.Close()

	go func() {
		dpu.KeepAlive(ctx)
	}()

	eventQueueReady := make(chan struct{})
	if dpu.EnableEventStream {
		go func() {
			dpu.EventConnect(ctx, eventQueueReady)
		}()
	}

	<-eventQueueReady

	if dpu.EnableEventStream {
		go func() {
			dpu.IPCEventListener(ctx)
		}()
	}

	go func() {
		dpu.ConfigConnect(ctx)
	}()

	go func() {
		dpu.PolicyConnect(ctx)
	}()

	<-ctx.Done()
	logger.GetLogger().Info("Streaming client connection closed")
	return nil
}
