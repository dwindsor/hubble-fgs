// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package nxos

import (
	"context"
	"sync"

	"github.com/isovalent/hubble-fgs/pkg/grpc/haclt"
	"github.com/isovalent/hubble-fgs/pkg/model/switchpolicy"
	model "github.com/isovalent/hubble-fgs/pkg/nxosmodel"
	hav1 "github.com/isovalent/hubble-fgs/pkg/proto/ha/v1"

	"github.com/openconfig/gnmic/pkg/api/target"
	"golang.design/x/chann"
)

const (
	initRetryCount     = 60
	initRetryInterval  = 10 // in second
	notifRetryCount    = 60
	notifRetryInterval = 30 // in second
)

const (
	RegFailK8sAuth = "invalid k8s service account token"
	RegOk          = ""
	ConnOk         = "connected ok with Hypershield controller"
	ConnFailed     = "failed to connect with Hypershield controller"
)

const (
	SysStFwDisable   = 0x0
	SysStDpuPending  = 0x1
	SysStConnPending = 0x2
	SysStDpuReady    = 0x4
	SysStRedirDone   = 0x8
)

type VrfBd struct {
	// for VRF, System/inst-items/Inst-list/dom-items
	// for BD, System/bd-items/bd-items/bd-list/BD-list
	Name      string
	IsGlobal  bool   // added via VRF context
	IsService bool   // added via fw policy
	IsStatic  bool   // static pinning
	Affinity  uint16 // static assigned dpu

	// the following are set by agent
	DpuPinned uint16 // dpu pinning
}

type Alloc struct {
	// next global id to be allocated
	Next uint16
	// global ID allocated to vrf's
	Gids map[string]uint16
	// dpu's pinned to vrf's
	VrfDpus map[string]uint16
	// dpu's pinned to bd's
	BdDpus map[string]uint16
}

type HaPeer struct {
	SkipAuth   bool
	IpConfigOk bool
	// revisit for N switch group proto
	State hav1.MBR_STATE
}

type HaAdj struct {
	Connected  bool
	GrpcClient haclt.Ha
	Epoch      int64 // in sec
}

type HaMbr struct {
	Info  hav1.MbrInfo
	Epoch int64 // in sec
}

type HaAlloc struct {
	Gids map[string]uint16
}

type HaCrit string

const (
	HaCritDpuHealth HaCrit = "dpu healthy"
	HaCritDpuInSync HaCrit = "dpu insync"
	HaCritSvcRedir  HaCrit = "service redir ok"
	HaCritPolicy    HaCrit = "policy ok"
)

type HaLocal struct {
	IsFunc   bool
	Epoch    int64
	Criteria map[HaCrit]bool
}

type HaNxStates struct {
	HaState       hav1.HA_STATE
	SvcState      hav1.SERVICE_STATE
	HaStateEpoch  int64
	SvcStateEpoch int64
}

type Ha struct {
	// System/sas-items/ha-items
	HaIp       string
	ClientCa   string
	ClientCert string
	ClientKey  string

	// config from nxos
	configured bool
	enabled    bool
	operUp     bool
	peers      map[string]HaPeer

	// peer info: key peer ha ip
	Adjacencies map[string]HaAdj
	Members     map[string]HaMbr
	Alloc       map[string]HaAlloc
	FlowSync    map[string]bool // sync FROM peer ok

	// local policy state
	Watching bool
	PolHash  string
	PolRev   string

	// derived local and remote
	Local    HaLocal
	Partners map[string]struct{}

	// states to nx
	NxStates HaNxStates

	// HA oper state
	Start    int64
	IsLeader bool
}

type Dpu struct {
	// System/sas-items/dpu-items/inst-items/Inst-list[name=$name]
	HaPorts string
	// System/sas-items/dpu-items/inst-items/Inst-list[name=$name]/ext-items
	Name    string
	Ip      string
	Port    uint16
	State   model.E_Cisco_NX_OSDevice_Sas_DpuStateE
	Version string // MainFwVer
	// the following are set by agent
	DpError     string
	AsicState   string // trigger switch reboot
	HaSyncState string
}

type Agent struct {
	// System/sas-items/sagent-items/ext-items
	InitState model.E_Cisco_NX_OSDevice_Sas_CommonStateE
	// the following are set by agent
	PolicyState model.E_Cisco_NX_OSDevice_Sas_CommonStateE
	// System/sas-items/sagent-items/ext-items
	SystemState int
}

type Ctrlr struct {
	// System/sas-items/scontroller-items
	Token     string
	ProxySvr  string
	ProxyPort uint32
	// the following are set by agent, System/sas-items/scontroller-items/ext-items
	Version          string
	RejectReason     string
	AdmissionStatus  model.E_Cisco_NX_OSDevice_Sas_CommonStateE
	ConnectionStatus model.E_Cisco_NX_OSDevice_Sas_CommonStateE
}

type Stage string

const (
	StageEnable Stage = "enable stage"
	StageDpu    Stage = "dpu stage"
	StageVrf    Stage = "vrf stage"
	StageNormal Stage = "normal stage"
)

const (
	WakeEnable = "wake enable"
	WakeInit   = "wake init"
	WakeDpu    = "wake dpu"
	WakeToken  = "wake token"
	WakeHa     = "wake ha"
)

type UpdatePersist struct {
	Id      string
	Type    string
	Version string
}

type UpdateResult struct {
	Success bool
	ErrCode int
	ErrMsg  string
}

type Update struct {
	// pkgaction status
	Status string
	// value from update.json
	Persist UpdatePersist
	// deployment result
	HasRes bool // result ready
	Result UpdateResult
}

type Nxos struct {
	sync.RWMutex
	Target *target.Target

	// operational
	Stage         Stage
	Wait          *chann.Chann[string]
	WaitHa        *chann.Chann[string]
	SkipReg       bool
	SkipRegReason string
	Reload        bool
	Alloc         Alloc
	AllocPrev     Alloc
	GidsInUse     map[uint16]string
	LastNotif     int64
	InSync        []string
	OutOfSync     []string
	SkipDpu       bool
	SkipCtrlr     bool
	DpuPortLow    uint16
	DpuPortHigh   uint16
	IsDelSvcFw    bool

	// counters
	NumDpu uint16

	// configuration from NXOS
	Configured bool
	InService  bool
	Ctrlr      Ctrlr
	Agent      Agent
	DpuInvDone bool
	Dpus       map[string]Dpu
	Vrfs       map[string]VrfBd
	Bds        map[string]VrfBd
	Ha         Ha
	Update     Update
	LbMode     model.E_Cisco_NX_OSDevice_Sas_LbModeType
	DpuVersion string
	serviceIp  string
	Model      string
	SwVer      string
	CpaVer     string
	SerNum     string

	// smartswitch management
	policyHandler switchpolicy.PolicyHandler
	dpuListener   *switchpolicy.DPUListener
}

type INxos interface {
	Setup(context.Context) error
	SetRegFail(context.Context, string)
	SetRegOk(context.Context, string)
	SetConnFail(context.Context, string)
	IsSkipReg() (bool, bool, string)
	SetServiceIp(string)
	GetServiceIp() string
	ShowStatus(context.Context) string
	ShowVrf(context.Context) string
	DelTokens(context.Context) string
	CheckUpdate(context.Context) string
	StartUpdate(context.Context, string, string, string, string) error
	GetNumDpu() uint16
}
