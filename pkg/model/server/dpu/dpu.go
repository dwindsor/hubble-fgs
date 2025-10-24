package dpu

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
	"text/tabwriter"
	"time"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"

	"github.com/isovalent/hubble-fgs/pkg/model/record"

	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"

	"google.golang.org/grpc"
)

const (
	dpuTimeout = 6 // in second

	// DPU IP mappings
	AgentIdDpu1 = "169.254.28.1"
	AgentIdDpu2 = "169.254.24.1"
	AgentIdDpu3 = "169.254.36.1"
	AgentIdDpu4 = "169.254.32.1"
)

var (
	dpuCount = 4 // HACK: need to configure this to change to 2 for deschutes
)

type DPUSubject struct {
	Cidr     string
	MinPort  uint32
	MaxPort  uint32
	Vlan     uint32
	VrfId    uint32
	Vrf      string
	Protocol v1alpha.PolicyProtocol
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
	Oper   v1alpha.PolicyOperation
	Policy *DPURule
}

type DPUReportStatus struct {
	AgentUid       string
	DpVersion      string
	AgentVersion   string
	PolicyChecksum string
	Hostname       string
	Architecture   string
	OS             string
	Type           v1alpha.AgentType
	SerialNumber   string
}

// Peer UID is unique in scope of agent so we never remove peers. And we expect
// only some small reasonable number of peers because these are physical offload
// engines.
type peer struct {
	uid        string
	polCh      chan *DPUPolicyRule
	cfgCh      chan *v1alpha.StreamDatapathConfigResponse
	cfgSet     map[v1alpha.ConfigType]*v1alpha.ConfigObject
	lastStatus DPUReportStatus
	lastEpoch  int64
	mtx        sync.RWMutex
}

func (p *peer) String() string {
	l := &p.lastStatus
	return fmt.Sprintf("%s: Hostname %s:%s:%s Serial %s",
		l.AgentUid, l.Hostname, l.Architecture, l.OS, l.SerialNumber)
}

type DPUListener struct {
	ctx       context.Context
	address   string
	peerGroup map[string]*peer
	ruleSet   map[[sha256.Size]byte]*DPURule
	mtx       sync.RWMutex
}

func NewDPUListener(ctx context.Context, address string) *DPUListener {
	return &DPUListener{
		ctx:       ctx,
		address:   address,
		peerGroup: make(map[string]*peer),
		ruleSet:   make(map[[sha256.Size]byte]*DPURule),
	}
}

func (dpu *DPUListener) Start() error {
	lis, err := net.Listen("tcp", dpu.address)
	if err != nil {
		return fmt.Errorf("policy server failed: %s", err)
	}

	logger.GetLogger().Info("DPU listener online")
	grpcServer := grpc.NewServer()
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

func (dpu *DPUListener) Checksum() [sha256.Size]byte {
	dpu.mtx.RLock()
	defer dpu.mtx.RUnlock()

	var vals []string
	var buf string

	for csum := range dpu.ruleSet {
		vals = append(vals, string(csum[:]))
	}
	sort.Strings(vals)
	for _, v := range vals {
		buf += v + ":"
	}
	return sha256.Sum256([]byte(buf))
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
		if s.lastStatus.PolicyChecksum != hexChecksum {
			logger.GetLogger().Error("failed state check", "dpu", s.uid, "expectedChecksum", hexChecksum, "actualChecksum", s.lastStatus.PolicyChecksum)
			stateCheck = false
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

func (dpu *DPUListener) StatusReportString() string {
	csum := dpu.Checksum()
	hexChecksum := hex.EncodeToString(csum[:])

	buf := new(bytes.Buffer)
	w := tabwriter.NewWriter(buf, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "LastPing\tUID\tHost\tAgent\tDatapath\tPolicySync")
	dpu.mtx.RLock()
	defer dpu.mtx.RUnlock()
	//fixme
	for _, s := range dpu.peerGroup {
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

		status := s.lastStatus
		sync := ""
		if status.PolicyChecksum == hexChecksum {
			sync = "true"
		} else {
			sync = fmt.Sprintf("false (%x != %s)", string(csum[:]), status.PolicyChecksum)
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			timeStatus,
			status.AgentUid,
			status.Hostname,
			status.AgentVersion,
			status.DpVersion,
			sync)
	}
	w.Flush()
	return buf.String()
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
	err = binary.Write(h, binary.BigEndian, rule.Source.MinPort)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	err = binary.Write(h, binary.BigEndian, rule.Source.MaxPort)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
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
	err = binary.Write(h, binary.BigEndian, rule.Source.Protocol)
	if err != nil {
		return [sha256.Size]byte{}, err
	}

	// Destination
	_, err = io.WriteString(h, rule.Destination.Cidr)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	err = binary.Write(h, binary.BigEndian, rule.Destination.MinPort)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	err = binary.Write(h, binary.BigEndian, rule.Destination.MaxPort)
	if err != nil {
		return [sha256.Size]byte{}, err
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
	err = binary.Write(h, binary.BigEndian, rule.Destination.Protocol)
	if err != nil {
		return [sha256.Size]byte{}, err
	}

	var result [sha256.Size]byte
	copy(result[:], h.Sum(nil))
	return result, nil
}

func (dpu *DPUListener) SubmitUpdateToDPU(record *record.DatapathRecord) error {
	rule := recordToDPUPolicyRule(record, true)
	return dpu.SubmitDPURuleToDPU(rule)
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

	// Trying to send the rule into the peer channel, but timing out after 3 seconds
	for _, dpu := range dpu.peerGroup {
		select {
		case dpu.polCh <- rule:
		case <-time.After(3 * time.Second):
			logger.GetLogger().Error("peer timed out, cannot submit rule", "peer", dpu.uid, "rule", *rule)
		}
	}

	return nil
}

func (dpu *DPUListener) SubmitDeleteToDPU(record *record.DatapathRecord) error {
	rule := recordToDPUPolicyRule(record, false)
	return dpu.SubmitDPURuleToDPU(rule)
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
		peer.cfgCh <- &resp
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
		peer.mtx.RLock()
		defer peer.mtx.RUnlock()
		dpuCfg, err := getPerDpuConfig(fullCfg, peer.uid)
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
		peer.cfgCh <- &resp
	}

	return nil
}
