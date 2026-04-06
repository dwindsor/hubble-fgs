// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package switchpolicy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"

	"github.com/isovalent/hubble-fgs/pkg/model/switchevents/policystatus"

	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
)

const (
	dpuTimeout        = 6  // in seconds
	dpuSyncErrorCount = 18 // number of StateCheck() calls that need to fail to force reconnect peer (every 10 seconds)
	// needs to be at least 180 seconds total
	missingFieldString = "N/A"
)

var (
	// DPU IP mappings to DPU number
	DPUMap = map[string]int{
		"169.254.28.1":  1,
		"169.254.24.1":  2,
		"169.254.36.1":  3,
		"169.254.32.1":  4,
		"169.254.151.1": 1,
		"169.254.159.1": 2,
	}
)

type DPUPorts struct {
	MinPort  uint32
	MaxPort  uint32
	Protocol v1alpha.PolicyProtocol
}

type DPUSubject struct {
	Cidr  string
	Ports *[]SmartSwitchNetworkProtocolPorts
	Vlan  uint32
	VrfId uint32
	Vrf   string
}

type DPURule struct {
	K8SResourceVersion string
	K8SUid             string
	K8SIndex           uint32
	PolicyName         string
	RuleName           string
	Action             v1alpha.PolicyAction
	Source             DPUSubject
	Destination        DPUSubject
}

// RuleUID returns a unique identifier for this rule based on its metadata.
func (r *DPURule) RuleUID() string {
	return r.K8SResourceVersion + ":" + r.K8SUid + ":" + r.PolicyName + ":" + r.RuleName
}

type DPUPolicyRule struct {
	Oper      v1alpha.PolicyOperation
	Timestamp time.Time
	Policy    *DPURule
}

type DPUReportStatus struct {
	AgentUid       string                 `json:"agent_uid"`
	DpVersion      string                 `json:"dp_version"`
	AgentVersion   string                 `json:"agent_version"`
	PolicyChecksum string                 `json:"policy_checksum"`
	Hostname       string                 `json:"hostname"`
	Architecture   string                 `json:"architecture"`
	OS             string                 `json:"os"`
	Type           v1alpha.AgentType      `json:"type"`
	SerialNumber   string                 `json:"serial_number"`
	HardwareModel  string                 `json:"hardware_model"`
	DpuReboot      uint32                 `json:"dpu_reboot"`      // Complete DPU reboot
	LastDpuReboot  *timestamppb.Timestamp `json:"last_dpu_reboot"` // Last DPU reboot time
	DpRestart      uint32                 `json:"dp_restart"`      // DP crash (corresponds to reboot time)
	LastDpCrash    *timestamppb.Timestamp `json:"last_dp_crash"`   // Last DP crash time
	LastFwaCrash   *timestamppb.Timestamp `json:"last_fwa_crash"`  // Last FWA crash time
	PortLow        uint32                 `json:"port_low"`
	PortHigh       uint32                 `json:"port_high"`
}

// DPUDisplayStatus is a display-friendly version of DPU status with computed fields.
// All fields have JSON tags for use with the generic table formatter.
type DPUDisplayStatus struct {
	LastPing          string `json:"lastPing"`
	Healthy           bool   `json:"healthy"`
	DPU               int    `json:"dpu"`
	UID               string `json:"uid"`
	Hardware          string `json:"hardware"`
	Agent             string `json:"agent"`
	Datapath          string `json:"datapath"`
	DpuReboot         uint32 `json:"dpuReboot"`
	LastDpuRebootTime string `json:"lastDpuRebootTime"`
	DpCrash           uint32 `json:"dpCrash"`
	LastDpCrashTime   string `json:"lastDpCrashTime"`
	LastFwaCrashTime  string `json:"lastFwaCrashTime"`
	DpuReconnects     uint32 `json:"dpuReconnects"`
	PolicySync        string `json:"policySync"`
}

// Peer UID is unique in scope of agent so we never remove peers. And we expect
// only some small reasonable number of peers because these are physical offload
// engines.
type peer struct {
	uid               string
	polCh             chan *DPUPolicyRule
	polReconnectCh    chan struct{}
	polReconnectCount atomic.Uint32 // Count of policy stream reconnections
	cfgCh             chan *v1alpha.StreamDatapathConfigResponse
	cfgReconnectCh    chan struct{}
	cfgReconnectCount atomic.Uint32 // Count of config stream reconnections
	cfgSet            map[v1alpha.ConfigType]*v1alpha.ConfigObject
	syncFailCount     atomic.Uint32
	lastStatus        DPUReportStatus
	lastEpoch         int64
	mtx               sync.RWMutex
}

func (p *peer) String() string {
	l := &p.lastStatus
	return fmt.Sprintf("%s: Hostname %s:%s:%s Serial %s",
		l.AgentUid, l.Hostname, l.Architecture, l.OS, l.SerialNumber)
}

func (p *peer) SendPolicy(rule *DPUPolicyRule) error {
	logger.GetLogger().Debug("Agw server: Sending policy rule to peer", "peerID", p.uid, "policyName", rule.Policy.PolicyName, "ruleName", rule.Policy.RuleName)

	// Check channel availability before sending
	if p.polCh == nil {
		logger.GetLogger().Error("Policy channel is nil, cannot send rule",
			"peerID", p.uid,
			"policyName", rule.Policy.PolicyName,
			"ruleName", rule.Policy.RuleName)
		return fmt.Errorf("policy channel is nil for peer %s", p.uid)
	}
	select {
	case p.polCh <- rule:
		// FIXME: this needs to be shorter than 1 second, as 1000 rules CANNOT take 1000 seconds to apply across DPUs
		// but making it shorter runs the risk of skipping a rule because the channel is busy and right now we do not
		// reconcile rules between FWA and AGW outside of the initial grpc connection, so if we skip a rule it is""i"
		// lost until the next reconnect
	case <-time.After(2 * time.Second):
		return fmt.Errorf("peer timed out, cannot submit policy rule")
	}
	return nil
}

func (p *peer) SendConfig(cfg *v1alpha.StreamDatapathConfigResponse) error {
	select {
	case p.cfgCh <- cfg:
	case <-time.After(2 * time.Second):
		// Force stream reconnect so AGW can replay config from cfgSet on reconnect.
		select {
		case p.cfgReconnectCh <- struct{}{}:
		default:
		}
		return fmt.Errorf("peer timed out, cannot submit config object")
	}
	return nil
}

// HaEventHandler receives HA events from DPUs and updates local HA criteria.
type HaEventHandler interface {
	RegisterDpu(ctx context.Context, dpuUid string)
	UpdateKeepalive(ctx context.Context, dpuUid string, up bool)
	UpdateBulkSyncLocal(ctx context.Context, dpuUid string, done bool)
	UpdateBulkSyncPeer(ctx context.Context, dpuUid string, done bool)
	UpdatePolicyRevision(ctx context.Context, revision string)
}

var haEventHandler HaEventHandler

// SetHaEventHandler sets the handler used for HA events from DPUs.
func SetHaEventHandler(h HaEventHandler) {
	haEventHandler = h
}

type DPUListener struct {
	ctx     context.Context
	address string

	// peerGroupSize refers to the expected number of peers, not the current size of peerGroup map
	peerGroupSize uint16
	peerGroup     map[string]*peer

	ruleSet        map[[sha256.Size]byte]*DPURule
	ruleUIDToHash  map[string][sha256.Size]byte // reverse index: RuleUID -> current hash
	cachedChecksum [sha256.Size]byte
	checksumValid  bool
	mtx            sync.RWMutex

	// Add PolicyStatusHandler
	policyStatusHandler policystatus.PolicyStatusHandler
}

func NewDPUListener(ctx context.Context, address string) *DPUListener {
	return &DPUListener{
		ctx:           ctx,
		address:       address,
		peerGroup:     make(map[string]*peer),
		ruleSet:       make(map[[sha256.Size]byte]*DPURule),
		ruleUIDToHash: make(map[string][sha256.Size]byte),
		peerGroupSize: 1,
	}
}

func (dpu *DPUListener) Start() error {
	lis, err := net.Listen("tcp", dpu.address)
	if err != nil {
		return fmt.Errorf("policy server failed: %s", err)
	}

	logger.GetLogger().Info("DPU listener online")
	grpcServer := grpc.NewServer(grpc.KeepaliveParams(keepalive.ServerParameters{
		Time:    1 * time.Second,
		Timeout: 3 * time.Second,
	}), grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
		MinTime: 1 * time.Second,
	}))
	v1alpha.RegisterL3L4NetworkPolicyServiceServer(grpcServer, newServer(dpu))
	logger.GetLogger().Info("DPU listener starting", "address", dpu.address)

	go func() {
		<-dpu.ctx.Done()
		logger.GetLogger().Info("DPU listener graceful shutdown")
		timer := time.AfterFunc(10*time.Second, func() {
			logger.GetLogger().Warn("DPU listener couldn't stop gracefully in time. Doing force stop.")
			grpcServer.Stop()
		})
		defer timer.Stop()
		grpcServer.GracefulStop()
		logger.GetLogger().Info("DPU listener closed gracefully")
	}()

	return grpcServer.Serve(lis)
}

func (dpu *DPUListener) SetPeerGroupSize(size uint16) {
	dpu.mtx.Lock()
	defer dpu.mtx.Unlock()
	dpu.peerGroupSize = size
}

func (dpu *DPUListener) Checksum() [sha256.Size]byte {
	// Checking the cached checksum first using only a read lock
	dpu.mtx.RLock()
	if dpu.checksumValid {
		defer dpu.mtx.RUnlock()
		return dpu.cachedChecksum
	}
	dpu.mtx.RUnlock()

	// Acquiring a write lock to update the checksum
	dpu.mtx.Lock()
	defer dpu.mtx.Unlock()

	keys := make([][]byte, 0, len(dpu.ruleSet))
	for csum := range dpu.ruleSet {
		keys = append(keys, csum[:])
	}
	sort.Slice(keys, func(x, y int) bool {
		return bytes.Compare(keys[x], keys[y]) <= 0
	})
	sep := []byte(":")
	joinedRules := bytes.Join(keys, sep)
	dpu.cachedChecksum = sha256.Sum256([]byte(joinedRules))
	dpu.checksumValid = true
	return dpu.cachedChecksum
}

func (dpu *DPUListener) GetDPUStatus() ([]DPUReportStatus, error) {
	dpu.mtx.RLock()
	defer dpu.mtx.RUnlock()

	stats := make([]DPUReportStatus, 0)

	for _, p := range dpu.peerGroup {
		stats = append(stats, p.lastStatus)
	}
	return stats, nil
}

func (dpu *DPUListener) StateCheck() bool {
	csum := dpu.Checksum()
	hexChecksum := hex.EncodeToString(csum[:])

	dpu.mtx.RLock()
	defer dpu.mtx.RUnlock()
	stateCheck := true

	for _, s := range dpu.peerGroup {
		currentFailCount := s.syncFailCount.Load()
		timeSinceLastUpdate := time.Now().Unix() - s.lastEpoch

		if currentFailCount >= dpuSyncErrorCount {
			logger.GetLogger().Error("DPU sync error threshold exceeded, forcing policy reconnect",
				"uid", s.uid,
				"failCount", currentFailCount,
				"threshold", dpuSyncErrorCount,
				"peerChecksum", s.lastStatus.PolicyChecksum,
				"expectedChecksum", hexChecksum,
				"timeSinceLastUpdate", timeSinceLastUpdate,
				"polReconnectCount", s.polReconnectCount.Load())

			// Force policy reconnect by signaling the channel (send, not
			// close) to avoid a race where addPeerLocked recreates the
			// channel between close+nil and the stream handler's next
			// select iteration, causing the signal to be lost entirely.
			// This matches the cfgReconnectCh pattern used for config.
			if s.polReconnectCh != nil {
				select {
				case s.polReconnectCh <- struct{}{}:
				default:
				}
			}
			logger.GetLogger().Warn("DPU sync timeout error, forcing policy reconnect", "uid", s.uid)
			// On reset restore the fail count to zero so that we
			// avoid going into a reset storm if it doesn't immediately
			// get in sync. This happens with large policies where the
			// time to sync may be larger or close to a single sync
			// interval.
			s.syncFailCount.Store(0)
		}

		if s.lastStatus.PolicyChecksum != hexChecksum {
			stateCheck = false
			s.syncFailCount.Add(1)

			logger.GetLogger().Error("Policy sync failure detected",
				"dpu", s.uid,
				"failCount", s.syncFailCount.Load(),
				"expectedChecksum", hexChecksum,
				"actualChecksum", s.lastStatus.PolicyChecksum,
				"checksumMismatch", true,
				"timeSinceLastUpdate", timeSinceLastUpdate,
				"peerVersion", s.lastStatus.AgentVersion,
				"peerDatapath", s.lastStatus.DpVersion,
				"polReconnectCount", s.polReconnectCount.Load())
			continue
		}
	}

	// Log overall state check result
	logger.GetLogger().Debug("Policy state check completed",
		"overallSyncStatus", stateCheck,
		"totalPeers", len(dpu.peerGroup),
		"expectedChecksum", hexChecksum)

	return stateCheck
}

func (dpu *DPUListener) HealthCheck() (bool, int) {
	dpu.mtx.RLock()
	defer dpu.mtx.RUnlock()

	now := time.Now().Unix()
	healthy := true
	count := len(dpu.peerGroup)
	for _, s := range dpu.peerGroup {
		if now-s.lastEpoch > dpuTimeout {
			healthy = false
			break
		}
	}
	return healthy, count
}

// GetDisplayStatuses returns the display-friendly status for all DPU peers, sorted by DPU ID.
func (dpu *DPUListener) GetDisplayStatuses() []DPUDisplayStatus {
	csum := dpu.Checksum()
	hexChecksum := hex.EncodeToString(csum[:])

	dpu.mtx.RLock()
	defer dpu.mtx.RUnlock()

	displayStatuses := make([]DPUDisplayStatus, 0, len(dpu.peerGroup))
	for _, s := range dpu.peerGroup {
		displayStatuses = append(displayStatuses, dpu.toDisplayStatus(s, csum, hexChecksum))
	}

	// Sort by DPU ID for consistent ordering
	sort.Slice(displayStatuses, func(i, j int) bool {
		return displayStatuses[i].DPU < displayStatuses[j].DPU
	})

	return displayStatuses
}

// toDisplayStatus converts a peer to a DPUDisplayStatus for table display.
func (dpu *DPUListener) toDisplayStatus(s *peer, csum [sha256.Size]byte, hexChecksum string) DPUDisplayStatus {
	now := time.Now().Unix()
	epochDiff := now - s.lastEpoch

	var timeStatus string
	if epochDiff < 60 {
		timeStatus = fmt.Sprintf("%ds", epochDiff)
	} else {
		minutes := epochDiff / 60
		seconds := epochDiff % 60
		timeStatus = fmt.Sprintf("%dm %ds", minutes, seconds)
	}

	healthy := epochDiff <= dpuTimeout
	status := s.lastStatus

	var syncStatus string
	if status.PolicyChecksum == hexChecksum {
		syncStatus = "true"
	} else {
		syncStatus = fmt.Sprintf("false (%x != %s)", csum[:], status.PolicyChecksum)
	}

	dpuNumber, ok := DPUMap[status.AgentUid]
	if !ok {
		dpuNumber = -1
	}

	var lastRebootStr string
	if status.LastDpuReboot != nil {
		lastRebootStr = status.LastDpuReboot.AsTime().Format(time.RFC3339)
	} else {
		lastRebootStr = missingFieldString
	}

	var lastCrashStr string
	if status.LastDpCrash != nil {
		lastCrashStr = status.LastDpCrash.AsTime().Format(time.RFC3339)
	} else {
		lastCrashStr = missingFieldString
	}

	var lastFwaCrashStr string
	if status.LastFwaCrash != nil {
		lastFwaCrashStr = status.LastFwaCrash.AsTime().Format(time.RFC3339)
	} else {
		lastFwaCrashStr = missingFieldString
	}

	return DPUDisplayStatus{
		LastPing:          timeStatus,
		DpuReconnects:     s.polReconnectCount.Load() - 1, // Subtracting one for the first connection
		Healthy:           healthy,
		DPU:               dpuNumber,
		UID:               status.AgentUid,
		Hardware:          status.HardwareModel,
		Agent:             status.AgentVersion,
		Datapath:          status.DpVersion,
		DpuReboot:         status.DpuReboot,
		LastDpuRebootTime: lastRebootStr,
		DpCrash:           status.DpRestart,
		LastDpCrashTime:   lastCrashStr,
		LastFwaCrashTime:  lastFwaCrashStr,
		PolicySync:        syncStatus,
	}
}

func HashRule(rule *DPURule) ([sha256.Size]byte, error) {
	h := sha256.New()

	// Write all fields in fixed order
	_, err := io.WriteString(h, rule.K8SResourceVersion)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	_, err = io.WriteString(h, rule.K8SUid)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	_, err = io.WriteString(h, rule.PolicyName)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	_, err = io.WriteString(h, rule.RuleName)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	err = binary.Write(h, binary.BigEndian, rule.Action)
	if err != nil {
		return [sha256.Size]byte{}, err
	}

	// Source
	_, err = io.WriteString(h, rule.Source.Cidr)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	/*
		for _, p := range *rule.Source.Ports {
			err = binary.Write(h, binary.BigEndian, p.Port)
			if err != nil {
				return [sha256.Size]byte{}, err
			}
			err = binary.Write(h, binary.BigEndian, p.EndPort)
			if err != nil {
				return [sha256.Size]byte{}, err
			}
			err = binary.Write(h, binary.BigEndian, p.Protocol)
			if err != nil {
				return [sha256.Size]byte{}, err
			}
		}
	*/
	err = binary.Write(h, binary.BigEndian, rule.Source.Vlan)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	err = binary.Write(h, binary.BigEndian, rule.Source.VrfId)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	_, err = io.WriteString(h, rule.Source.Vrf)
	if err != nil {
		return [sha256.Size]byte{}, err
	}

	// Destination
	_, err = io.WriteString(h, rule.Destination.Cidr)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	for _, p := range *rule.Destination.Ports {
		err = binary.Write(h, binary.BigEndian, p.Port)
		if err != nil {
			return [sha256.Size]byte{}, err
		}
		err = binary.Write(h, binary.BigEndian, p.EndPort)
		if err != nil {
			return [sha256.Size]byte{}, err
		}
		err = binary.Write(h, binary.BigEndian, p.Protocol)
		if err != nil {
			return [sha256.Size]byte{}, err
		}
	}
	err = binary.Write(h, binary.BigEndian, rule.Destination.Vlan)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	err = binary.Write(h, binary.BigEndian, rule.Destination.VrfId)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	_, err = io.WriteString(h, rule.Destination.Vrf)
	if err != nil {
		return [sha256.Size]byte{}, err
	}

	var result [sha256.Size]byte
	copy(result[:], h.Sum(nil))
	return result, nil
}

func (dpu *DPUListener) SubmitDPURuleToDPU(rule *DPUPolicyRule) error {
	// Snapshot peers while holding the lock for the ruleSet mutation, then
	// release before fanning out to peers. SendPolicy can block on channel
	// sends with a 2s timeout per peer; holding the write lock during that
	// I/O starves every other caller (StateCheck, addPeer, gRPC streams).
	peers, err := func() (map[string]*peer, error) {
		dpu.mtx.Lock()
		defer dpu.mtx.Unlock()

		csum, err := HashRule(rule.Policy)
		if err != nil {
			logger.GetLogger().Error("Failed to hash policy rule",
				"policyName", rule.Policy.PolicyName,
				"ruleName", rule.Policy.RuleName,
				"error", err)
			return nil, err
		}

		hexCsum := hex.EncodeToString(csum[:])
		logger.GetLogger().Debug("Processing policy rule submission",
			"operation", rule.Oper.String(),
			"policyName", rule.Policy.PolicyName,
			"ruleName", rule.Policy.RuleName,
			"ruleChecksum", hexCsum[:16], // First 16 chars
			"currentRuleSetSize", len(dpu.ruleSet),
			"targetPeers", len(dpu.peerGroup))

		uid := rule.Policy.RuleUID()

		switch rule.Oper {
		case v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT:
			// If this rule UID already exists with a different hash (e.g., VRF ID
			// change), remove the old hash entry so it doesn't linger in the ruleSet.
			if oldCsum, ok := dpu.ruleUIDToHash[uid]; ok && oldCsum != csum {
				delete(dpu.ruleSet, oldCsum)
			}
			dpu.ruleSet[csum] = rule.Policy
			dpu.ruleUIDToHash[uid] = csum
		case v1alpha.PolicyOperation_POLICY_OPERATION_DELETE:
			if _, exists := dpu.ruleSet[csum]; exists {
				delete(dpu.ruleSet, csum)
			} else {
				logger.GetLogger().Warn("Attempted to delete non-existent rule",
					"ruleChecksum", hexCsum[:16],
					"policyName", rule.Policy.PolicyName,
					"ruleName", rule.Policy.RuleName)
			}
			delete(dpu.ruleUIDToHash, uid)
		default:
			return nil, fmt.Errorf("unknown operation type %d", rule.Oper)
		}
		dpu.checksumValid = false

		// Snapshot the peer map so we can fan out without the lock.
		snapshot := make(map[string]*peer, len(dpu.peerGroup))
		for k, v := range dpu.peerGroup {
			snapshot[k] = v
		}
		return snapshot, nil
	}()
	if err != nil {
		return err
	}

	// Send to all peers without holding the lock.
	successCount := 0
	failureCount := 0
	for peerUID, p := range peers {
		err := p.SendPolicy(rule)
		if err != nil {
			failureCount++
			logger.GetLogger().Error("Failed to send policy rule to peer",
				"error", err,
				"peer", peerUID,
				"policyName", rule.Policy.PolicyName,
				"ruleName", rule.Policy.RuleName,
				"operation", rule.Oper.String(),
				"peerLastEpoch", p.lastEpoch,
				"peerFailCount", p.syncFailCount.Load())
		} else {
			successCount++
		}
	}

	logger.GetLogger().Debug("Policy rule distribution completed",
		"policyName", rule.Policy.PolicyName,
		"ruleName", rule.Policy.RuleName,
		"operation", rule.Oper.String(),
		"successCount", successCount,
		"failureCount", failureCount,
		"totalPeers", len(peers))

	return nil
}

func (dpu *DPUListener) addPeer(uid string) *peer {
	dpu.mtx.Lock()
	defer dpu.mtx.Unlock()
	return dpu.addPeerLocked(uid)
}

func (dpu *DPUListener) addPeerLocked(uid string) *peer {
	p, ok := dpu.peerGroup[uid]
	if !ok {
		p = &peer{
			uid: uid,
		}
		dpu.peerGroup[uid] = p
		logger.GetLogger().Info("Added peer DPU", "uid", uid)
	}

	if p.polCh == nil {
		logger.GetLogger().Info("Added peer DPU l3l4 netpol channel", "uid", uid)
		p.polCh = make(chan *DPUPolicyRule)
	}

	if p.cfgCh == nil {
		logger.GetLogger().Info("Added peer DPU config channel", "uid", uid)
		p.cfgCh = make(chan *v1alpha.StreamDatapathConfigResponse)
	}

	if p.cfgReconnectCh == nil {
		p.cfgReconnectCh = make(chan struct{}, 1)
	}

	if p.cfgSet == nil {
		p.cfgSet = make(map[v1alpha.ConfigType]*v1alpha.ConfigObject)
	}
	return p
}

// There is a slight abstraction leak hear with the request falling here and
// this is why grpc and dpu are one package. Perhaps there is a better
// abstraction, but at the moment this is simple and we can test it.
func (dpu *DPUListener) ReportStatus(status *DPUReportStatus) {
	peer := dpu.addPeer(status.AgentUid)
	peer.mtx.Lock()
	defer peer.mtx.Unlock()
	peer.lastStatus = *status
	peer.lastEpoch = time.Now().Unix()
}

// Implements the callback function defined as config/library.ConfigCallback.  This is passed as a callback function
// for any configuration that needs to be transparently passed to DPUs.
func (dpu *DPUListener) SubscribeConfig(oldCfg *v1alpha.ConfigObject, newCfg *v1alpha.ConfigObject) error {
	// Building the response object based on the old and new config objects
	resp := v1alpha.StreamDatapathConfigResponse{}
	if newCfg == nil { // Config was deleted
		resp.Oper = v1alpha.ConfigOperation_CONFIG_OPERATION_DELETE
		resp.Config = oldCfg
	} else {
		resp.Oper = v1alpha.ConfigOperation_CONFIG_OPERATION_UPSERT
		resp.Config = newCfg
	}

	// Push the response to all peers
	dpu.mtx.RLock()
	defer dpu.mtx.RUnlock()
	for _, peer := range dpu.peerGroup {
		err := peer.SendConfig(&resp)
		if err != nil {
			logger.GetLogger().Error("failed to send config object to peer", logfields.Error, err, "peer", peer.uid, "config", resp.Config.Config)
		}
	}
	return nil
}

// DPU Config is unique per DPU peer, so it needs extra logic to handle.  This is a custom callback function
// that is handles only library.ConfigTypeDpu type of config objects.
func (dpu *DPUListener) SubscribeDpuConfig(oldCfg *v1alpha.ConfigObject, newCfg *v1alpha.ConfigObject) error {
	// Building the response operation based on the old and new config objects and extracting the dpu object
	var oper v1alpha.ConfigOperation
	var fullCfg *v1alpha.DpuConfig
	if newCfg == nil && oldCfg != nil {
		oper = v1alpha.ConfigOperation_CONFIG_OPERATION_DELETE
		fullCfg = oldCfg.GetConfigDpu()
	} else if newCfg != nil {
		oper = v1alpha.ConfigOperation_CONFIG_OPERATION_UPSERT
		fullCfg = newCfg.GetConfigDpu()
	} else {
		logger.GetLogger().Error("dpu config callback function failed", logfields.Error, "both config objects are nil")
		return nil
	}

	// Iterating through all peers, building the config response, and pushing it
	dpu.mtx.RLock()
	defer dpu.mtx.RUnlock()
	for _, peer := range dpu.peerGroup {
		// Create a new response for each peer to avoid race conditions
		resp := v1alpha.StreamDatapathConfigResponse{
			Oper: oper,
		}
		// For delete operations, send empty config to FWA
		if oper == v1alpha.ConfigOperation_CONFIG_OPERATION_DELETE {
			resp.Config = &v1alpha.ConfigObject{
				Type:   v1alpha.ConfigType_CONFIG_TYPE_DPU,
				Source: v1alpha.ConfigSource_CONFIG_SOURCE_LOCAL,
				Config: &v1alpha.ConfigObject_ConfigDpu{ConfigDpu: &v1alpha.DpuConfig{}},
			}
		} else {
			dpuCfg, err := getPerDpuConfig(fullCfg, peer.uid, dpu.peerGroupSize)
			if err != nil {
				logger.GetLogger().Error("dpu config callback function failed", logfields.Error, err)
				continue
			}

			// Push the response to the peer
			resp.Config = &v1alpha.ConfigObject{
				Type:   v1alpha.ConfigType_CONFIG_TYPE_DPU,
				Source: v1alpha.ConfigSource_CONFIG_SOURCE_LOCAL,
				Config: &v1alpha.ConfigObject_ConfigDpu{ConfigDpu: dpuCfg},
			}
		}
		err := peer.SendConfig(&resp)
		if err != nil {
			logger.GetLogger().Error("failed to send config object to peer", logfields.Error, err, "peer", peer.uid, "config", resp.Config)
		}
	}

	return nil
}

// HA Config is unique per DPU peer, so it needs extra logic to handle. This is a custom callback function
// that handles only library.ConfigTypeHa type of config objects.
func (dpu *DPUListener) SubscribeHaConfig(oldCfg *v1alpha.ConfigObject, newCfg *v1alpha.ConfigObject) error {
	// Building the response operation based on the old and new config objects and extracting the ha object
	var oper v1alpha.ConfigOperation
	var fullCfg *v1alpha.HaConfig
	if newCfg == nil && oldCfg != nil {
		oper = v1alpha.ConfigOperation_CONFIG_OPERATION_DELETE
		fullCfg = oldCfg.GetConfigHa()
	} else if newCfg != nil {
		oper = v1alpha.ConfigOperation_CONFIG_OPERATION_UPSERT
		fullCfg = newCfg.GetConfigHa()
	} else {
		logger.GetLogger().Error("ha config callback function failed", logfields.Error, "both config objects are nil")
		return nil
	}

	// Iterating through all peers, building the config response, and pushing it
	dpu.mtx.RLock()
	defer dpu.mtx.RUnlock()
	for _, peer := range dpu.peerGroup {
		// Create a new response for each peer to avoid race conditions
		resp := v1alpha.StreamDatapathConfigResponse{
			Oper: oper,
		}
		// For delete operations, send empty config to FWA
		if oper == v1alpha.ConfigOperation_CONFIG_OPERATION_DELETE {
			resp.Config = &v1alpha.ConfigObject{
				Type:   v1alpha.ConfigType_CONFIG_TYPE_HA,
				Source: v1alpha.ConfigSource_CONFIG_SOURCE_LOCAL,
				Config: &v1alpha.ConfigObject_ConfigHa{ConfigHa: &v1alpha.HaConfig{}},
			}
		} else {
			haCfg, err := getPerDpuHaConfig(fullCfg, peer.uid, dpu.peerGroupSize)
			if err != nil {
				logger.GetLogger().Error("ha config callback function failed", logfields.Error, err)
				continue
			}

			// Push the response to the peer
			resp.Config = &v1alpha.ConfigObject{
				Type:   v1alpha.ConfigType_CONFIG_TYPE_HA,
				Source: v1alpha.ConfigSource_CONFIG_SOURCE_LOCAL,
				Config: &v1alpha.ConfigObject_ConfigHa{ConfigHa: haCfg},
			}
		}
		err := peer.SendConfig(&resp)
		if err != nil {
			logger.GetLogger().Error("failed to send config object to peer", logfields.Error, err, "peer", peer.uid, "config", resp.Config)
		}
	}

	return nil
}

// SetPolicyStatusHandler sets the policy status handler for the DPU listener.
// This method is thread-safe and will acquire a lock before updating the handler.
// The handler parameter should implement the PolicyStatusHandler interface and will
// be used to handle policy status updates for this DPU listener instance.
func (dpu *DPUListener) SetPolicyStatusHandler(handler policystatus.PolicyStatusHandler) {
	dpu.mtx.Lock()
	defer dpu.mtx.Unlock()
	dpu.policyStatusHandler = handler
}

// GetPolicyStatusHandler retrieves the current policy status handler for the DPU listener.
// This method is thread-safe and will acquire a read lock before accessing the handler.
// It returns the PolicyStatusHandler interface that is currently set for this DPU listener instance.
func (dpu *DPUListener) GetPolicyStatusHandler() policystatus.PolicyStatusHandler {
	dpu.mtx.RLock()
	defer dpu.mtx.RUnlock()
	return dpu.policyStatusHandler
}
