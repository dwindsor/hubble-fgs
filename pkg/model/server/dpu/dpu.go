package dpu

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"text/tabwriter"

	"github.com/cilium/tetragon/pkg/logger"

	"github.com/isovalent/hubble-fgs/pkg/model/record"

	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"

	"google.golang.org/grpc"
)

type DPUSubject struct {
	Cidr     string
	MinPort  uint32
	MaxPort  uint32
	Vlan     uint32
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
	ch         chan *DPUPolicyRule
	lastStatus DPUReportStatus
}

func (p *peer) String() string {
	l := &p.lastStatus
	return fmt.Sprintf("%s: Hostname %s:%s:%s Serial %s",
		l.AgentUid, l.Hostname, l.Architecture, l.OS, l.SerialNumber)
}

type DPUListener struct {
	ctx       context.Context
	port      int
	host      string
	peerGroup map[string]*peer
	ruleSet   map[[sha256.Size]byte]*DPURule
}

var (
	// DPU Listener is a singleton there is one and only one AGW/Tetragon
	// agent and many DPUs.
	dpu *DPUListener
)

func NewDPUListener(ctx context.Context, host string, port int) *DPUListener {
	dpu = &DPUListener{
		ctx:       ctx,
		port:      port,
		host:      host,
		peerGroup: make(map[string]*peer),
		ruleSet:   make(map[[sha256.Size]byte]*DPURule),
	}
	return dpu
}

func GetDPUListener() *DPUListener {
	return dpu
}

func (dpu *DPUListener) Start() error {
	lis, err := net.Listen("tcp", fmt.Sprintf("%s:%d", dpu.host, dpu.port))
	if err != nil {
		return fmt.Errorf("policy server failed: %s", err)
	}

	logger.GetLogger().Info("DPU listener online")

	for {
		select {
		case <-dpu.ctx.Done():
			lis.Close()
			logger.GetLogger().Info("DPU listener closing")
			return nil
		default:
			grpcServer := grpc.NewServer()
			v1alpha.RegisterL3L4NetworkPolicyServiceServer(grpcServer, newServer())
			logger.GetLogger().Info("DPU listener starting")
			grpcServer.Serve(lis)
		}
	}
}

func (dpu *DPUListener) Checksum() [sha256.Size]byte {
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
	stats := make([]DPUReportStatus, 0)

	for _, p := range dpu.peerGroup {
		stats = append(stats, p.lastStatus)
	}
	return stats, nil
}

func (dpu *DPUListener) StateCheck() bool {
	csum := dpu.Checksum()
	hexChecksum := hex.EncodeToString(csum[:])

	for _, s := range dpu.peerGroup {
		if s.lastStatus.PolicyChecksum != hexChecksum {
			return false
		}
	}
	return true
}

func (dpu *DPUListener) StatusReportString() string {
	csum := dpu.Checksum()
	hexChecksum := hex.EncodeToString(csum[:])

	buf := new(bytes.Buffer)
	w := tabwriter.NewWriter(buf, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "UID\tHost\tAgent\tDatapath\tPolicySync")
	//fixme
	for _, s := range dpu.peerGroup {
		status := s.lastStatus
		sync := ""
		if status.PolicyChecksum == hexChecksum {
			sync = "true"
		} else {
			sync = fmt.Sprintf("false (%x != %s)", string(csum[:]), status.PolicyChecksum)
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			status.AgentUid,
			status.Hostname,
			status.AgentVersion,
			status.DpVersion,
			sync)
	}
	w.Flush()
	return buf.String()
}

func hashRule(rule *DPURule) ([sha256.Size]byte, error) {
	var buf bytes.Buffer

	// fixme
	enc := gob.NewEncoder(&buf) // Will write to network.
	err := enc.Encode(*rule)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(buf.Bytes()), nil
}

func (dpu *DPUListener) SubmitUpdateToDPU(record *record.DatapathRecord) error {
	rule := recordToDPUPolicyRule(record, true)
	csum, err := hashRule(rule.Policy)
	if err != nil {
		return err
	}
	dpu.ruleSet[csum] = rule.Policy
	for _, dpu := range dpu.peerGroup {
		dpu.ch <- rule
	}
	return nil
}

func (dpu *DPUListener) SubmitDeleteToDPU(record *record.DatapathRecord) error {
	rule := recordToDPUPolicyRule(record, false)
	csum, err := hashRule(rule.Policy)
	if err != nil {
		return err
	}
	delete(dpu.ruleSet, csum)

	for _, peer := range dpu.peerGroup {
		peer.ch <- rule
	}
	return nil
}

func (dpu *DPUListener) addPeer(uid string) *peer {
	p, ok := dpu.peerGroup[uid]
	if !ok {
		p = &peer{
			uid: uid,
		}
		dpu.peerGroup[uid] = p
		logger.GetLogger().Info("Added peer DPU", "uid", uid)
	}

	if p.ch == nil {
		logger.GetLogger().Info("Added peer DPU l3l4 netpol channel", "uid", uid)
		p.ch = make(chan *DPUPolicyRule)
	}
	return p
}

// There is a slight abstraction leak hear with the request falling here and
// this is why grpc and dpu are one package. Perhaps there is a better
// abstraction, but at the moment this is simple and we can test it.
func (dpu *DPUListener) ReportStatus(status *DPUReportStatus) {
	peer := dpu.addPeer(status.AgentUid)
	peer.lastStatus = *status
}
