package dpu

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/version"

	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"

	"github.com/isovalent/hubble-fgs/pkg/config"
	"github.com/isovalent/hubble-fgs/pkg/config/library"
	"github.com/isovalent/hubble-fgs/pkg/dpu/dataplane"
	"github.com/isovalent/hubble-fgs/pkg/dpu/events"
	"github.com/isovalent/hubble-fgs/pkg/dpu/exporter"
	agentDPU "github.com/isovalent/hubble-fgs/pkg/model/server/dpu"
	"github.com/isovalent/hubble-fgs/pkg/utils"
)

const (
	BUFSIZE = 4096

	// on firewall.*, use ens5. on real dpu, int_mnic0
	DPU_INTERFACE = "int_mnic0"

	EXPORTER_CONFIG_PATH    = "/data/hypershield/daflogger.yaml" // HACK: need to update config to pass this path
	EVENTLOGGER_SOCKET_PATH = "/tmp/fluentbit_fwa.sock"          // HACK: need to pass through config
)

type StreamClient struct {
	client       v1alpha.L3L4NetworkPolicyServiceClient
	ctx          context.Context
	conn         *grpc.ClientConn
	policyStream grpc.ServerStreamingClient[v1alpha.Streaml3L4NetworkPolicyResponse]
	configStream grpc.ServerStreamingClient[v1alpha.StreamDatapathConfigResponse]
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
		ruleSet:       make(map[[sha256.Size]byte]*agentDPU.DPURule),
		serverAddress: server,
		ruleSetLock:   sync.Mutex{},
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

	Dataplane   dataplane.Dataplane
	LogExporter exporter.Exporter

	Cfg          *config.Config
	EventLogger  *events.EventLogger
	Retries      int
	streamClient *StreamClient
	// This uses the sha of the PolicyRule as the key. The value though is
	// the message. We SHA256 the rule so that the operation matches for
	// both UPSERT and DELETE. To get a Set sha256 we can take the sha256
	// of the concatenated strings in this map.
	ruleSet     map[[sha256.Size]byte]*agentDPU.DPURule
	ruleSetLock sync.Mutex
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

func (dpu *DPUAgent) Config(ctx context.Context, configPath string, dpSocketPath string, enableDataplane bool, enableLogger bool) error {
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
	logger.GetLogger().Info("Connected to dataplane", "type", dpu.Dataplane.Type(), "version", dpu.Dataplane.Version())

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
			return err
		}
		err = dpu.Dataplane.RefreshConfig(oldCfg, newCfg)
		if err != nil {
			return err
		}
		return nil
	}
	dpuConfigCallback := func(oldCfg *v1alpha.ConfigObject, newCfg *v1alpha.ConfigObject) error {
		err := dpu.Dataplane.RefreshConfig(oldCfg, newCfg)
		if err != nil {
			return err
		}
		err = dpu.LogExporter.RefreshConfig(oldCfg, newCfg)
		if err != nil {
			return err
		}
		return nil
	}

	// Adding config callbacks
	library.GetRepository().AddConfigCallback(v1alpha.ConfigType_CONFIG_TYPE_DPU, dpuConfigCallback)
	library.GetRepository().AddConfigCallback(v1alpha.ConfigType_CONFIG_TYPE_LOG_SYSLOG, logConfigCallback)
	library.GetRepository().AddConfigCallback(v1alpha.ConfigType_CONFIG_TYPE_LOG_IPFIX, logConfigCallback)
	library.GetRepository().AddConfigCallback(v1alpha.ConfigType_CONFIG_TYPE_LOG_TIMESCAPE, logConfigCallback)

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
	var vals []string
	var buf string

	dpu.ruleSetLock.Lock()
	defer dpu.ruleSetLock.Unlock()

	for csum := range dpu.ruleSet {
		vals = append(vals, string(csum[:]))
	}
	sort.Strings(vals)
	for _, v := range vals {
		buf += v + ":"
	}
	return sha256.Sum256([]byte(buf))
}

func (dpu *DPUAgent) upsertPolicyRule(rule *agentDPU.DPUPolicyRule) {

	csum, err := agentDPU.HashRule(rule.Policy)
	if err != nil {
		logger.GetLogger().Error("Failed policy rule checksum, corrupted policy",
			logfields.Error, err, "rule", rule)
		return
	}

	dpu.ruleSetLock.Lock()
	defer dpu.ruleSetLock.Unlock()
	dpu.ruleSet[csum] = rule.Policy
}

func (dpu *DPUAgent) deletePolicyRule(rule *agentDPU.DPUPolicyRule) {
	csum, err := agentDPU.HashRule(rule.Policy)
	if err != nil {
		logger.GetLogger().Error("Failed policy rule checksum, corrupted policy",
			logfields.Error, err)
		return
	}

	dpu.ruleSetLock.Lock()
	defer dpu.ruleSetLock.Unlock()
	delete(dpu.ruleSet, csum)
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

		rule := agentDPU.ResponseToDPURule(resp)
		policyList := []*agentDPU.DPUPolicyRule{rule}

		switch resp.Oper {
		case v1alpha.PolicyOperation_POLICY_OPERATION_UNSPECIFIED:
			logger.GetLogger().Error("failed policy, unknown operation")
		case v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT:
			dpu.upsertPolicyRule(rule)
			err := dpu.Dataplane.PushPolicy(ctx, v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT, policyList)
			if err != nil {
				logger.GetLogger().Error("upsert failed", logfields.Error, err)
				continue
			}

			// Log event
			msg := events.NewEventLogMessage(events.MSGCODE_POLICY, dpu.AgentId)
			msg.PolicyOperation = "upsert"
			msg.PolicyId = rule.Policy.PolicyName
			dpu.EventLogger.Log(msg)
		case v1alpha.PolicyOperation_POLICY_OPERATION_DELETE:
			dpu.deletePolicyRule(rule)
			err := dpu.Dataplane.PushPolicy(ctx, v1alpha.PolicyOperation_POLICY_OPERATION_DELETE, policyList)
			if err != nil {
				logger.GetLogger().Error("upsert failed", logfields.Error, err)
				continue
			}

			// Log event
			msg := events.NewEventLogMessage(events.MSGCODE_POLICY, dpu.AgentId)
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
			msg := events.NewEventLogMessage(events.MSGCODE_CONFIG, dpu.AgentId)
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
			msg := events.NewEventLogMessage(events.MSGCODE_CONFIG, dpu.AgentId)
			msg.ConfigOperation = "delete"
			msg.ConfigType = resp.Config.Type.String()
			dpu.EventLogger.Log(msg)
		}
	}
}

func (dpu *DPUAgent) KeepAlive(ctx context.Context) error {
	// arbitrarily chosen to be 1 second there are not many DPUs in
	// the same node and this makes us overly responsive to rule set
	// hashes which is nice.
	keepAliveTimer := time.Second
	for {
		select {
		case <-ctx.Done():
			logger.GetLogger().Info("Stopping keep-alive")
			return nil
		case <-time.After(keepAliveTimer):
			csum := dpu.Checksum()
			status := &v1alpha.ReportStatus{
				AgentUid:       dpu.AgentId,
				DpVersion:      dpu.Dataplane.Version(),
				AgentVersion:   dpu.Version(),
				PolicyChecksum: hex.EncodeToString(csum[:]),
				Hostname:       dpu.Hostname,
				Architecture:   dpu.Architecture,
				Os:             dpu.Os,
				Type:           v1alpha.AgentType_AGENT_TYPE_DPU_AGW,
				SerialNumber:   "serialNumber",
			}
			req := &v1alpha.ReportStatusRequest{
				Status: status,
			}
			_, err := dpu.streamClient.client.ReportStatus(ctx, req)
			if err != nil {
				logger.GetLogger().Error("keep alive report status error",
					logfields.Error, err)
			}
		}
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

			logger.GetLogger().Info("Network Policy listening...")
			if err := dpu.PolicyEventLoop(ctx); err != nil {
				logger.GetLogger().Error("policy event loop aborted", logfields.Error, err)
			}
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

func (dpu *DPUAgent) Connect(ctx context.Context) error {
	var err error

	dpu.streamClient = &StreamClient{}

	logger.GetLogger().Info("Starting Streaming client")
	dpu.streamClient.conn, err = grpc.NewClient(
		dpu.serverAddress,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
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

	go func() {
		dpu.PolicyConnect(ctx)
	}()

	go func() {
		dpu.ConfigConnect(ctx)
	}()

	<-ctx.Done()
	logger.GetLogger().Info("Streaming client connection closed")
	return nil
}
