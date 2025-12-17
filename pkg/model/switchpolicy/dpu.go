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
	PolicyName         string
	RuleName           string
	Action             v1alpha.PolicyAction
	Source             DPUSubject
	Destination        DPUSubject
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
	select {
	case p.polCh <- rule:
	// FIXME: this needs to be shorter than 1 second, as 1000 rules CANNOT take 1000 seconds to apply across DPUs
	// but making it shorter runs the risk of skipping a rule because the channel is busy and right now we do not
	// reconcile rules between FWA and AGW outside of the initial grpc connection, so if we skip a rule it is
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
		return fmt.Errorf("peer timed out, cannot submit config object")
	}
	return nil
}

type DPUListener struct {
	ctx     context.Context
	address string

	// peerGroupSize refers to the expected number of peers, not the current size of peerGroup map
	peerGroupSize uint16
	peerGroup     map[string]*peer

	ruleSet map[[sha256.Size]byte]*DPURule
	mtx     sync.RWMutex
}

func NewDPUListener(ctx context.Context, address string) *DPUListener {
	return &DPUListener{
		ctx:           ctx,
		address:       address,
		peerGroup:     make(map[string]*peer),
		ruleSet:       make(map[[sha256.Size]byte]*DPURule),
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
	dpu.mtx.RLock()
	defer dpu.mtx.RUnlock()

	keys := make([][]byte, 0, len(dpu.ruleSet))

	for csum := range dpu.ruleSet {
		keys = append(keys, csum[:])
	}
	sort.Slice(keys, func(x, y int) bool {
		return bytes.Compare(keys[x], keys[y]) <= 0
	})
	sep := []byte(":")
	joinedRules := bytes.Join(keys, sep)
	return sha256.Sum256([]byte(joinedRules))
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
		if s.syncFailCount.Load() > dpuSyncErrorCount {
			// Force policy reconnect by closing the channel
			if s.polReconnectCh != nil {
				close(s.polReconnectCh)
				s.polReconnectCh = nil
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
			logger.GetLogger().Error("failed state check", "dpu", s.uid, "failCount", s.syncFailCount.Load(), "expectedChecksum", hexChecksum, "actualChecksum", s.lastStatus.PolicyChecksum)
			continue
		}
	}
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
	dpu.mtx.Lock()
	defer dpu.mtx.Unlock()

	csum, err := HashRule(rule.Policy)
	if err != nil {
		return err
	}
	switch rule.Oper {
	case v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT:
		dpu.ruleSet[csum] = rule.Policy
	case v1alpha.PolicyOperation_POLICY_OPERATION_DELETE:
		delete(dpu.ruleSet, csum)
	default:
		return fmt.Errorf("unknown operation type %d", rule.Oper)
	}

	for _, dpu := range dpu.peerGroup {
		err := dpu.SendPolicy(rule)
		if err != nil {
			logger.GetLogger().Error("failed to send policy rule to peer", logfields.Error, err, "peer", dpu.uid, "rule", *rule)
		}
	}

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

	if p.polReconnectCh == nil {
		p.polReconnectCh = make(chan struct{})
	}

	if p.cfgCh == nil {
		logger.GetLogger().Info("Added peer DPU config channel", "uid", uid)
		p.cfgCh = make(chan *v1alpha.StreamDatapathConfigResponse)
	}

	if p.cfgReconnectCh == nil {
		p.cfgReconnectCh = make(chan struct{})
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
	resp := v1alpha.StreamDatapathConfigResponse{}
	var fullCfg *v1alpha.DpuConfig
	if newCfg == nil && oldCfg != nil {
		resp.Oper = v1alpha.ConfigOperation_CONFIG_OPERATION_DELETE
		fullCfg = oldCfg.GetConfigDpu()
	} else if newCfg != nil {
		resp.Oper = v1alpha.ConfigOperation_CONFIG_OPERATION_UPSERT
		fullCfg = newCfg.GetConfigDpu()
	} else {
		logger.GetLogger().Error("dpu config callback function failed", logfields.Error, "both config objects are nil")
		return nil
	}

	// Iterating through all peers, building the config response, and pushing it
	dpu.mtx.RLock()
	defer dpu.mtx.RUnlock()
	for _, peer := range dpu.peerGroup {
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
		err = peer.SendConfig(&resp)
		if err != nil {
			logger.GetLogger().Error("failed to send config object to peer", logfields.Error, err, "peer", peer.uid, "config", resp.Config.Config)
		}
	}

	return nil
}
