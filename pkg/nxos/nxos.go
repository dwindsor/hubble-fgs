package nxos

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"io/ioutil"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"
	model "github.com/isovalent/hubble-fgs/pkg/nxosmodel"

	"github.com/openconfig/gnmic/pkg/api"
	"github.com/openconfig/ygot/ytypes"
	"github.com/spf13/viper"
	"golang.design/x/chann"
)

const (
	svcInst = "System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]"
	seqNum  = 10

	TokenFile             = "/iox_data/cpa_tokens"
	waitForDpuInterval    = 10  // in second
	waitForInSyncInterval = 30  // in second
	notifTimeout          = 900 // in second
)

const (
	initGlobalId = 10
)

var Nexus Nxos

func (n *Nxos) initiate(ctx context.Context) error {
	ip, ok := os.LookupEnv("NX_GRPC_IP")
	if !ok {
		logger.Fatal(logger.GetLogger(), "NX_GRPC_IP missing")
	}
	port, ok := os.LookupEnv("NX_GRPC_PORT")
	if !ok {
		port = "50052"
		logger.GetLogger().Debug("NX_GRPC_PORT missing, use default", "port", port)
	}
	user, ok := os.LookupEnv("NX_GRPC_USER")
	if !ok {
		user = "__svc_sas_control"
		logger.GetLogger().Debug("NX_GRPC_USER missing, use default", "user", user)
	}

	viper.SetConfigFile("/etc/sas.cfg")
	viper.SetConfigType("env")
	err := viper.ReadInConfig()
	if err != nil {
		logger.Fatal(logger.GetLogger(), "ReadInConfig fails", logfields.Error, err)
	}
	pass := viper.GetString("NX_GRPC_PASS")
	if pass == "" {
		logger.Fatal(logger.GetLogger(), "Fail to get NX_GRPC_PASS")
	}
	var skipDpu bool
	sd := viper.GetString("NX_AGENT_IGNORE_MODULES")
	if sd == "1" {
		skipDpu = true
		logger.GetLogger().Debug("Skip DPUs")
	}
	var skipCtrlr bool
	sc := viper.GetString("NX_AGENT_HEADLESS_MODE")
	if sc == "1" {
		skipCtrlr = true
		logger.GetLogger().Debug("Headless mode")
	}

	// delete rpm files used for update
	deleteUpdateRpms(ctx)

	// restore persisted update info
	var persist UpdatePersist
	err = n.load(ctx, updateFname, &persist)
	if err != nil && !os.IsNotExist(err) {
		logger.GetLogger().Error("fail to load persisted update info", logfields.Error, err)
	} else {
		logger.GetLogger().Debug("Persisted update info", "info", persist)
		n.Update.Persist = persist
	}

	// set up signal handling
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		logger.GetLogger().Debug("Received signal:", "sig", sig)
		n.RLock()
		n.cleanup(ctx)
		n.RUnlock()
		n.GnmiClose(ctx)
		os.Exit(201)
	}()

	// create a target
	tg, err := api.NewTarget(
		api.Name("sswitch"),
		api.Address(ip+":"+port),
		api.Username(user),
		api.Password(pass),
		api.SkipVerify(true),
		//api.Insecure(true),
	)
	if err != nil {
		logger.GetLogger().Error("Fail to create target", logfields.Error, err)
		return err
	}

	// create a gNMI client
	err = tg.CreateGNMIClient(ctx)
	if err != nil {
		logger.GetLogger().Error("Fail to create client", logfields.Error, err)
		return err
	}
	n.Target = tg

	// restore persisted data
	n.restore(ctx)

	// reset connection status
	n.Agent.SystemState = SysStDpuPending

	// get admission and connection states
	jstrs, err := n.gnmiGet(ctx, svcInst+"/scontroller-items/ext-items")
	if err != nil {
		logger.GetLogger().Error("Fail to get scontroller-items/ext-items", logfields.Error, err)
		return err
	}
	if len(jstrs) > 0 && len(jstrs[0]) > 0 {
		items := &model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_ScontrollerItems_ExtItems{}
		opts := []ytypes.UnmarshalOpt{&ytypes.IgnoreExtraFields{}}
		err = model.Unmarshal([]byte(jstrs[0]), items, opts...)
		if err != nil {
			logger.GetLogger().Error("Fail to unmarshal scontroller-items/ext-items", logfields.Error, err)
		} else {
			logger.GetLogger().Debug("scontroller/ext-items:", "items", items)
			n.Ctrlr.AdmissionStatus = items.AdmissionStatus
			n.Ctrlr.ConnectionStatus = items.ConnectionStatus
			if items.RejectReason != nil {
				n.Ctrlr.RejectReason = *items.RejectReason
			}
			if items.Version != nil {
				n.Ctrlr.Version = *items.Version
			}
		}
	} else {
		logger.GetLogger().Debug("Set admission and connection status to default")
		n.Ctrlr.AdmissionStatus = model.Cisco_NX_OSDevice_Sas_CommonStateE_unknown
		n.Ctrlr.ConnectionStatus = model.Cisco_NX_OSDevice_Sas_CommonStateE_unknown
	}
	n.ResetConn(ctx)

	// get proxy config
	jstrs, err = n.gnmiGet(ctx, svcInst+"/scontroller-items")
	if err != nil {
		logger.GetLogger().Error("Fail to get scontroller-items", logfields.Error, err)
		return err
	}
	// logger.GetLogger().Debug("jstrs: %v", jstrs)
	if len(jstrs) > 0 && len(jstrs[0]) > 0 {
		items := &model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_ScontrollerItems{}
		opts := []ytypes.UnmarshalOpt{&ytypes.IgnoreExtraFields{}}
		err = model.Unmarshal([]byte(jstrs[0]), items, opts...)
		if err != nil {
			logger.GetLogger().Error("Fail to unmarshal scontroller-items", logfields.Error, err)
		} else {
			// logger.GetLogger().Debug("scontroller-items: %+v", items)
			if items.HttpsProxySvr != nil {
				n.Ctrlr.ProxySvr = *items.HttpsProxySvr
			}
			if items.HttpsProxyPort != nil {
				n.Ctrlr.ProxyPort = *items.HttpsProxyPort
			}
			n.setProxy(ctx)
		}
	}

	// get model and nxos version
	jstrs, err = n.gnmiGet(ctx, "/System/ch-items/supslot-items")
	if err != nil {
		logger.GetLogger().Error("Fail to get supslot-items", logfields.Error, err)
		return err
	}
	// logger.GetLogger().Debug("jstrs: %v", jstrs)
	if len(jstrs) > 0 && len(jstrs[0]) > 0 {
		items := &model.Cisco_NX_OSDevice_System_ChItems_SupslotItems{}
		opts := []ytypes.UnmarshalOpt{&ytypes.IgnoreExtraFields{}}
		err = model.Unmarshal([]byte(jstrs[0]), items, opts...)
		if err != nil {
			logger.GetLogger().Error("Fail to unmarshal supslot-items", logfields.Error, err)
		} else {
			for _, list := range items.SupCSlotList {
				if list.SupItems == nil {
					continue
				}
				// logger.GetLogger().Debug("SupItems: %+v", list.SupItems)
				if list.SupItems.Model != nil && list.SupItems.SwVer != nil {
					n.Model = *list.SupItems.Model
					n.SwVer = *list.SupItems.SwVer
					logger.GetLogger().Debug("sswitch", "model", n.Model, "SwVer", n.SwVer)
					break
				}
			}
		}
	}

	jstrs, err = n.gnmiGet(ctx, "/System/ch-items/spbp-items/spcmn-items")
	if err != nil {
		logger.GetLogger().Error("Fail to get spcmn-items", logfields.Error, err)
		return err
	}
	logger.GetLogger().Debug("jstrs", "jstrs", jstrs)
	if len(jstrs) > 0 && len(jstrs[0]) > 0 {
		items := &model.Cisco_NX_OSDevice_System_ChItems_SpbpItems_SpcmnItems{}
		opts := []ytypes.UnmarshalOpt{&ytypes.IgnoreExtraFields{}}
		err = model.Unmarshal([]byte(jstrs[0]), items, opts...)
		if err != nil {
			logger.GetLogger().Error("Fail to unmarshal spcmn-items", logfields.Error, err)
		} else if items.SerNum != nil {
			n.SerNum = *items.SerNum
			logger.GetLogger().Debug("sswitch", "sernum", n.SerNum)
		}
	}

	n.Stage = StageEnable
	n.Wait = chann.New[string]()
	n.WaitHa = chann.New[string]()
	n.Dpus = make(map[string]Dpu)
	n.Vrfs = make(map[string]VrfBd)
	n.Bds = make(map[string]VrfBd)
	if n.AllocPrev.Next != 0 {
		n.Alloc.Next = n.AllocPrev.Next
	} else {
		n.Alloc.Next = initGlobalId
	}
	n.Alloc.Gids = make(map[string]uint16)
	n.Alloc.VrfDpus = make(map[string]uint16)
	n.Alloc.BdDpus = make(map[string]uint16)
	n.LastNotif = time.Now().Unix()
	n.SkipDpu = skipDpu
	n.SkipCtrlr = skipCtrlr
	n.Ha.Peers = make(map[string]HaPeer)
	n.Ha.Adjacencies = make(map[string]HaAdj)
	n.Ha.Members = make(map[string]HaMbr)
	n.Ha.FlowSync = make(map[string]bool)
	n.Ha.Local.Criteria = make(map[HaCrit]bool)
	n.Ha.Local.Criteria[HaCritDpuHealth] = false
	n.Ha.Local.Criteria[HaCritDpuInSync] = false
	n.Ha.Local.Criteria[HaCritSvcRedir] = false
	// HACK: set to true until integration with new policy
	n.Ha.Local.Criteria[HaCritPolicy] = true
	n.Ha.Partners = make(map[string]struct{})

	go n.haSetup(ctx)

	return nil
}

// unsubscribe all above gnmi subscriptions
func (n *Nxos) subscribe(ctx context.Context) {
	paths := []string{
		"System/sas-items/dpu-items",
		"System/sas-items/volatiledata-items/agent-items",
		"System/sas-items/globalpol-items",
		"System/sas-items/state-items/agent-items/SasAgent-list[svcName=hypershield]/agentSrcIntfAddr",
		"System/sas-items/state-items/agent-items/SasAgent-list[svcName=hypershield]/agentHaSrcIntfAddr",
		svcInst + "/scontroller-items",
		"System/inst-items/Inst-list/dom-items",
		svcInst + "/fwpolicy-items",
		"System/swpkgs-items/rpmaction-items",
		"System/bd-items/bd-items",
		svcInst + "/ha-items/adminState",
		svcInst + "/ha-items/nxHaOperState",
		svcInst + "/ha-items/peer-items",
	}

	logger.GetLogger().Debug("Subscribed", "paths", paths)
	go n.gnmiSubscribe(ctx, "nxos", paths)
}

func (n *Nxos) isInService(_ context.Context) bool {

	n.RLock()
	defer n.RUnlock()

	logger.GetLogger().Debug("InService:", "service", n.InService)
	return n.InService
}

// wait for service enabling
func (n *Nxos) waitForEnable(ctx context.Context) error {
	logger.GetLogger().Debug("Wait for service enabling")
	defer func() { n.Stage = StageDpu }()

	if n.Stage != StageEnable {
		err := errors.New("unexpected stage")
		logger.GetLogger().Error("stage", logfields.Error, err, "state", n.Stage)
		return err
	}

	if n.isInService(ctx) {
		return nil
	}

	for {
		select {
		case wait := <-n.Wait.Out():
			logger.GetLogger().Debug("Waked up", "wait", wait)
			if n.isInService(ctx) {
				return nil
			}
		}
	}
}

func (n *Nxos) isAllDpuCounted(_ context.Context) (uint16, bool) {

	n.RLock()
	defer n.RUnlock()

	if n.DpuInvDone && len(n.Dpus) == int(n.NumDpu) {
		logger.GetLogger().Debug("All DPUs counted", "DPUs", n.NumDpu)
		return n.NumDpu, true
	}
	return n.NumDpu, false
}

// wait for DPUs online
func (n *Nxos) waitForDpu(ctx context.Context) (uint16, error) {
	logger.GetLogger().Debug("Wait for DPUs")
	defer func() {
		n.Stage = StageToken
	}()

	if n.SkipDpu {
		logger.GetLogger().Debug("SkipDpu is true but still count DPU inventory")
	}

	if n.Stage != StageDpu {
		err := errors.New("unexpected stage")
		logger.GetLogger().Error("stage", logfields.Error, err, "stage", n.Stage)
		return 0, err
	}

	num, ok := n.isAllDpuCounted(ctx)
	if ok {
		return num, nil
	}

	for {
		select {
		case wait := <-n.Wait.Out():
			logger.GetLogger().Debug("Waked up", "time", wait)
			num, ok := n.isAllDpuCounted(ctx)
			if ok {
				return num, nil
			}
		}
	}
}

func (n *Nxos) isTokenAvail(_ context.Context) bool {
	n.RLock()
	defer n.RUnlock()

	return n.Ctrlr.Token != ""
}

// wait for HS controller token
func (n *Nxos) waitForToken(ctx context.Context) error {
	logger.GetLogger().Debug("Wait for token")
	defer func() { n.Stage = StageVrf }()

	if n.Stage != StageToken {
		err := errors.New("unexpected stage")
		logger.GetLogger().Error("stage", logfields.Error, err, "state", n.Stage)
		return err
	}

	if n.isTokenAvail(ctx) {
		return nil
	}

	for {
		select {
		case wait := <-n.Wait.Out():
			logger.GetLogger().Debug("Waked up", "time", wait)
			if n.isTokenAvail(ctx) {
				return nil
			}
		}
	}
}

// currently only handle VRF change
func (n *Nxos) waitForChange(ctx context.Context) error {
	logger.GetLogger().Debug("Wait for change")

	if n.Stage != StageNormal {
		err := errors.New("Unexpected stage")
		logger.GetLogger().Error("stage", logfields.Error, err, "stage", n.Stage)
		return err
	}
	n.HaUpdateCrit(ctx, HaCritSvcRedir, true)

	for {
		time.Sleep(time.Hour)
	}
}

func fnv1a(buf []byte) uint64 {
	hash := fnv.New64a()
	hash.Write(buf)
	return hash.Sum64()
}

func (n *Nxos) setFwPolicyStateAll(ctx context.Context) error {

	n.RLock()
	defer n.RUnlock()

	vrfs := []VrfBd{}
	for _, vrf := range n.Vrfs {
		vrfs = append(vrfs, vrf)
	}
	err := n.setFwPolicyState(ctx, false, vrfs)
	if err != nil {
		return err
	}

	bds := []VrfBd{}
	for _, bd := range n.Bds {
		bds = append(bds, bd)
	}
	err = n.setFwPolicyState(ctx, true, bds)
	return err
}

// for now use a fixed filter. will tune later
func (n *Nxos) setServiceRedirAll(ctx context.Context, isLock bool) error {
	logger.GetLogger().Debug("setServiceRedirAll:", "isLock", isLock)
	defer func() { n.Stage = StageNormal }()

	err := n.setAccessList(ctx)
	if err != nil {
		logger.GetLogger().Error("", logfields.Error, err)
		return err
	}

	if isLock {
		n.Lock()
		defer n.Unlock()
	}

	err = n.setServiceEndpointBd(ctx)
	if err != nil {
		logger.GetLogger().Error("", logfields.Error, err)
	}
	err = n.setPolicyMapBd(ctx)
	if err != nil {
		logger.GetLogger().Error("", logfields.Error, err)
	}

	vrfs := []VrfBd{}
	for _, vrf := range n.Vrfs {
		vrfs = append(vrfs, vrf)
	}
	err = n.setServiceRedir(ctx, false, vrfs)
	if err != nil {
		logger.GetLogger().Error("", logfields.Error, err)
	}

	bds := []VrfBd{}
	for _, bd := range n.Bds {
		bds = append(bds, bd)
	}
	err = n.setServiceRedir(ctx, true, bds)
	if err != nil {
		logger.GetLogger().Error("", logfields.Error, err)
	}

	return nil
}

func (n *Nxos) Setup(ctx context.Context, low, high uint16) error {

	n.DpuPortLow = low
	n.DpuPortHigh = high

	logger.GetLogger().Debug("Initiating CPA")
	err := n.initiate(ctx)
	if err != nil {
		logger.GetLogger().Error("Fail to initiate", logfields.Error, err)
		return err
	}
	logger.GetLogger().Debug("CPA initiated")

	n.subscribe(ctx)
	logger.GetLogger().Debug("NXOS subscribed")

	err = n.waitForEnable(ctx)
	if err != nil {
		logger.GetLogger().Error("Fail to wait for enable", logfields.Error, err)
		return err
	}
	logger.GetLogger().Debug("Service enabled")

	// DPU inventory-done pending and controller connection pending
	n.Agent.SystemState = SysStDpuPending | SysStConnPending
	err = n.setSystemState(ctx)
	if err != nil {
		logger.GetLogger().Error("Fail to set system state", logfields.Error, err)
	}

	dpuCnt, err := n.waitForDpu(ctx)
	if err != nil {
		logger.GetLogger().Error("Fail to wait for dpu", logfields.Error, err)
		return err
	}
	// I don't see any reason to wait for the DPUs to announce. Let the system come
	// online and we will deal with missing DPUs. I gather from waitForDpu above
	// the switch knows they exist.
	/*
		if !n.SkipDpu {
			for {
				fwaCnt := deploy.GetFwaCount(ctx)
				logger.GetLogger().Debug("FWACount", "dpu", dpuCnt, "fwa", fwaCnt)
				if int(dpuCnt) == fwaCnt {
					break
				}
				time.Sleep(waitForDpuInterval * time.Second)
			}
		}
	*/

	// set update result
	if n.Update.Persist.Id != "" {
		n.Update.HasRes = true
		for _, dpu := range n.Dpus {
			if n.Update.Persist.Version != dpu.Version && dpu.Version != "NA" {
				logger.GetLogger().Debug("persisted version does not match dpu version", "persistent", n.Update.Persist.Version, "dpuVersion", dpu.Version)
				n.Update.Result.ErrCode = int(1)
				n.Update.Result.ErrMsg = "Not running updated DPU firmware"
				break
			}
		}
		if n.Update.Result.ErrMsg == "" {
			n.Update.Result.Success = true
		}
	}
	logger.GetLogger().Debug("DPU ready:", "cnt", dpuCnt)

	if !n.SkipCtrlr {
		ht := haveTokens(ctx)
		if !ht {
			// wait for OTP from NXOS
			err = n.waitForToken(ctx)
			if err != nil {
				logger.GetLogger().Error("Fail to wait for token", logfields.Error, err)
				return err
			}
		}
	}
	logger.GetLogger().Debug("Token ready")

	go n.checkNotif(ctx)
	go n.setup(ctx, dpuCnt)

	if n.SkipCtrlr {
		logger.GetLogger().Debug("Skip connecting to controller")
		for {
			time.Sleep(time.Hour)
		}
	}

	return nil
}

func (n *Nxos) setup(ctx context.Context, dpuCnt uint16) {

	logger.GetLogger().Debug("Waiting for DPU in sync")
	if !n.SkipDpu {
		for {
			time.Sleep(waitForInSyncInterval * time.Second)
			n.RLock()
			logger.GetLogger().Debug("In Sync FWA", "count", len(n.InSync))
			if len(n.InSync) == int(dpuCnt) {
				n.RUnlock()
				break
			}
			n.RUnlock()
		}
	}
	// DPU sub-system ready for service firewall
	if (n.Agent.SystemState & SysStConnPending) == SysStConnPending {
		n.Agent.SystemState = SysStDpuReady | SysStConnPending
	} else {
		n.Agent.SystemState = SysStDpuReady
	}
	err := n.setSystemState(ctx)
	if err != nil {
		logger.GetLogger().Error("Fail to set system state", logfields.Error, err)
	}
	logger.GetLogger().Debug("policy ready")

	// reconciliation for service redir
	n.reconcile(ctx)

	// notify NXOS of VRF pinning
	err = n.setFwPolicyStateAll(ctx)
	if err != nil {
		logger.GetLogger().Error("Fail to set fw policy state", logfields.Error, err)
		return
	}
	logger.GetLogger().Debug("VRF pinning ready")

	// notify NXOS of service redir
	err = n.setServiceRedirAll(ctx, true)
	if err != nil {
		logger.GetLogger().Error("Fail to program service redir", logfields.Error, err)
	} else {
		logger.GetLogger().Debug("Service redir ready")

		// DPU sub-system ready and svc redir done
		n.Agent.SystemState |= 0x8
		err = n.setSystemState(ctx)
		if err != nil {
			logger.GetLogger().Error("Fail to set system state", logfields.Error, err)
		}
	}

	// handle incremental changes
	err = n.waitForChange(ctx)
	if err != nil {
		logger.Fatal(logger.GetLogger(), "Fail to wait for change", logfields.Error, err)
	}
}

// clean up all: connection status, systemState, PolicyState and service redir
func (n *Nxos) cleanup(ctx context.Context) {
	logger.GetLogger().Debug("clean up fw policy state, system state and service redir")

	// reset connection state
	n.ResetConn(ctx)

	for name, vrf := range n.Vrfs {
		if !vrf.IsGlobal || !vrf.IsService {
			continue
		}
		path := fmt.Sprintf("%s/fwpolicystate-items/ipvrfstate-items/dom-items/DomState-list[name=%s]/ext-items",
			svcInst, name)
		err := n.gnmiDel(ctx, path)
		if err != nil {
			logger.GetLogger().Error("", logfields.Error, err)
		}
	}

	for name, bd := range n.Bds {
		if !bd.IsGlobal || !bd.IsService {
			continue
		}
		path := fmt.Sprintf("%s/fwpolicystate-items/bdstate-items/vlan-items/VlanState-list[vlanId=%s]/ext-items",
			svcInst, name)
		err := n.gnmiDel(ctx, path)
		if err != nil {
			logger.GetLogger().Error("", logfields.Error, err)
		}
	}

	path := svcInst + "/sagent-items/ext-items/systemState"
	err := n.gnmiDel(ctx, path)
	if err != nil {
		logger.GetLogger().Error("", logfields.Error, err)
	}

	path = "/System/serviceredir-items"
	err = n.gnmiDel(ctx, path)
	if err != nil {
		logger.GetLogger().Error("", logfields.Error, err)
	}

	n.remove(ctx, allocFname)

	if n.haIsEnabled(ctx, false) {
		n.setLocalSvcStateToFailure(ctx)
	}
}

func (n *Nxos) setSkipReg(_ context.Context, reason string) {
	n.Lock()
	defer n.Unlock()

	n.SkipReg = true
	n.SkipRegReason = reason
}

func (n *Nxos) unsetSkipReg(_ context.Context, rl bool) {
	n.Reload = rl
	n.SkipReg = false
	n.SkipRegReason = ""
}

func (n *Nxos) IsSkipReg(_ context.Context) (bool, bool, string) {

	n.RLock()
	defer n.RUnlock()

	rl := n.Reload
	if rl {
		logger.GetLogger().Debug("reload auth")
		n.Reload = false
	}
	return n.SkipReg, rl, n.SkipRegReason
}

func (n *Nxos) reconcile(ctx context.Context) {

	n.RLock()
	defer n.RUnlock()

	for vrf, d := range n.AllocPrev.VrfDpus {
		logger.GetLogger().Debug("Reconcile previous VRF", "vrf", vrf)
		dpu, ok := n.Alloc.VrfDpus[vrf]
		if !ok {
			logger.GetLogger().Debug("Previous VRF deleted")
			// vrf deleted, clean up svc redir
			err := n.delServiceRedir(ctx, false, vrf)
			if err != nil {
				logger.GetLogger().Error("Fail to reconcile")
			}
		} else if n.isLbModePinning(ctx) && d != dpu ||
			!n.isLbModePinning(ctx) && d != allDpu {
			// repinning happens, delete endpoint
			err := n.delDpuEndpointVrf(ctx, vrf)
			if err != nil {
				logger.GetLogger().Error("Fail to reconcile", logfields.Error, err)
			}
		}
	}
	for bd, d := range n.AllocPrev.BdDpus {
		logger.GetLogger().Debug("Reconcile previous BD", "bd", bd)
		dpu, ok := n.Alloc.VrfDpus[bd]
		if !ok {
			logger.GetLogger().Debug("Previous BD deleted")
			// bd deleted, clean up svc redir
			err := n.delServiceRedir(ctx, true, bd)
			if err != nil {
				logger.GetLogger().Error("Fail to reconcile", logfields.Error, err)
			}
		} else if n.isLbModePinning(ctx) && d != dpu ||
			!n.isLbModePinning(ctx) && d != allDpu {

			// repinning happens, delete endpoint
			err := n.delPolicyEnfBd(ctx, bd)
			if err != nil {
				logger.GetLogger().Error("Fail to reconcile", logfields.Error, err)
			}
		}
	}
}

func (n *Nxos) checkNotif(_ context.Context) {
	logger.GetLogger().Debug("Start to check notification liveness")

	for {
		now := time.Now().Unix()
		logger.GetLogger().Debug("last notification", "now", now, "LastNotif", n.LastNotif)
		if now-n.LastNotif > notifTimeout {
			// right now just cry. TBD: graceful restart?
			logger.GetLogger().Error("Notification liveness fails")
		}
		time.Sleep(60 * time.Second)
	}
}

// restore VRF allocation of DPU and global ID from MO
// dn: /System/serviceredir-items/inst-items/service-items/Service-list
func (n *Nxos) restore(ctx context.Context) error {
	logger.GetLogger().Debug("Restore previous DPU/Gid allocation from MO")

	n.AllocPrev.Next = 0
	n.AllocPrev.Gids = make(map[string]uint16)
	n.AllocPrev.VrfDpus = make(map[string]uint16)
	n.AllocPrev.BdDpus = make(map[string]uint16)

	path := "System/serviceredir-items/inst-items/service-items"
	jstrs, err := n.gnmiGet(ctx, path)
	if err != nil {
		logger.GetLogger().Error("Fail to get service list", logfields.Error, err)
		return err
	}
	logger.GetLogger().Debug("jstrs:", "jstrs", jstrs)

	if len(jstrs) > 0 && len(jstrs[0]) > 0 {
		items := &model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems{}
		opts := []ytypes.UnmarshalOpt{&ytypes.IgnoreExtraFields{}}
		err = model.Unmarshal([]byte(jstrs[0]), items, opts...)
		if err != nil {
			logger.GetLogger().Error("Fail to unmarshal service-items", logfields.Error, err)
			return err
		}
		var next uint16
		for redir, list := range items.ServiceList {
			if list == nil || list.DpuepItems == nil {
				logger.GetLogger().Debug("Empty data for redir", "redir", redir)
				continue
			}
			if list.Type != model.Cisco_NX_OSDevice_Epbr_EpbrType_dpu {
				logger.GetLogger().Debug("Skip no VRF redir", "reidr", redir)
				continue
			}

			vrf := strings.TrimPrefix(redir, "__")
			vrf = strings.TrimSuffix(vrf, "_dpu_redir")
			for _, ep := range list.DpuepItems.SvcEndPointDpuList {
				if ep == nil {
					continue
				}
				if ep.Vlan != nil && ep.DpuNum != model.Cisco_NX_OSDevice_Sas_SvcModulePinning_UNSET {
					logger.GetLogger().Debug("AllocPrev populated for VRF", "vrf", vrf)
					n.AllocPrev.Gids[vrf] = *ep.Vlan
					n.AllocPrev.VrfDpus[vrf] = mod2dpu(ctx, ep.DpuNum)
					if *ep.Vlan >= next {
						next = *ep.Vlan + 1
					}
					// for now consider single dpu
					break
				}
			}
		}
		n.AllocPrev.Next = next
	}

	path = "System/serviceredir-items/inst-items/bd-items"
	jstrs, err = n.gnmiGet(ctx, path)
	if err != nil {
		logger.GetLogger().Error("Fail to get bd list", logfields.Error, err)
		return err
	}
	logger.GetLogger().Debug("jstrs: %+v", "jstrs", jstrs)

	if len(jstrs) > 0 && len(jstrs[0]) > 0 {
		items := &model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_BdItems{}
		opts := []ytypes.UnmarshalOpt{&ytypes.IgnoreExtraFields{}}
		err = model.Unmarshal([]byte(jstrs[0]), items, opts...)
		if err != nil {
			logger.GetLogger().Error("Fail to unmarshal bd-items", logfields.Error, err)
			return err
		}
		for id, list := range items.BDList {
			if list == nil || list.Policy == nil {
				logger.GetLogger().Debug("Empty data for BD", "bd", id)
				continue
			}

			dpu := name2dpu(ctx, *list.Policy)
			n.AllocPrev.BdDpus[id] = dpu
		}
	}

	logger.GetLogger().Debug("AllocPrev:", "prev", n.AllocPrev)
	return nil
}

func (n *Nxos) buildProxy(_ context.Context) string {
	var proxy string

	if n.Ctrlr.ProxySvr == "" {
		logger.GetLogger().Debug("proxy not set")
		return proxy
	}
	proxy = "https://" + n.Ctrlr.ProxySvr
	if n.Ctrlr.ProxyPort != 0 {
		proxy += fmt.Sprintf(":%d", n.Ctrlr.ProxyPort)
	}
	logger.GetLogger().Debug("proxy:", "proxy", proxy)
	return proxy
}

func (n *Nxos) setProxy(ctx context.Context) {

	proxy := n.buildProxy(ctx)
	if proxy == "" {
		return
	}
	err := os.Setenv(envHttpProxy, proxy)
	if err != nil {
		logger.GetLogger().Error("Fail to set http proxy", logfields.Error, err)
	}
	err = os.Setenv(envHttpsProxy, proxy)
	if err != nil {
		logger.GetLogger().Error("Fail to set https proxy", logfields.Error, err)
	}
	err = os.Setenv(envHttpProxy2, proxy)
	if err != nil {
		logger.GetLogger().Error("Fail to set http proxy 2", logfields.Error, err)
	}
	err = os.Setenv(envHttpsProxy2, proxy)
	if err != nil {
		logger.GetLogger().Error("Fail to set https proxy 2", logfields.Error, err)
	}
	n.store(ctx, ctrlrFname, n.Ctrlr)
}

func (n *Nxos) GetOtp() string {
	return n.Ctrlr.Token
}

func haveTokens(_ context.Context) bool {

	finfo, err := os.Stat(TokenFile)
	if err != nil {
		logger.GetLogger().Error("Fail to stat token file", logfields.Error, err)
		return false
	}
	if finfo.Size() == 0 {
		return false
	}
	return true
}

func SetInSyncCount(ctx context.Context, insync, oosync []string) {
	Nexus.Lock()
	if len(insync) == int(Nexus.NumDpu) && Nexus.Ha.Local.Criteria != nil {
		Nexus.haUpdateCrit(ctx, HaCritDpuInSync, true)
	} else if Nexus.Ha.Local.Criteria != nil {
		Nexus.haUpdateCrit(ctx, HaCritDpuInSync, false)
	}
	Nexus.InSync = insync
	Nexus.OutOfSync = oosync
	Nexus.Unlock()
}

func (n *Nxos) CheckUpdateStatus(_ context.Context) string {

	n.RLock()
	defer n.RUnlock()

	status := n.Update.Status
	if status != "" {
		logger.GetLogger().Debug("CheckUpdateStatuss", "status", status)
		n.Update.Status = ""
	}
	return status
}

func (n *Nxos) CheckUpdateResult(ctx context.Context) (bool, bool, UpdatePersist, UpdateResult) {
	n.Lock()
	defer n.Unlock()

	if n.Update.Persist.Id == "" {
		logger.GetLogger().Debug("No update info persisted")
		return false, false, n.Update.Persist, n.Update.Result
	} else if n.Update.HasRes {
		logger.GetLogger().Debug("Update result ready", "result", n.Update.Result)
		n.remove(ctx, updateFname)
		return false, true, n.Update.Persist, n.Update.Result
	} else {
		return true, false, n.Update.Persist, n.Update.Result
	}
}

func (n *Nxos) isLbModePinning(_ context.Context) bool {
	if n.LbMode == model.Cisco_NX_OSDevice_Sas_LbModeType_symmetric_hash {
		logger.GetLogger().Debug("isLbModePinning: false")
		return false
	}
	logger.GetLogger().Debug("isLbModePinning: true")
	return true
}

func (n *Nxos) CheckDpuVersion() string {
	n.Lock()
	defer n.Unlock()

	return n.DpuVersion
}

func deleteUpdateRpms(_ context.Context) {
	logger.GetLogger().Debug("deleteUpdateRpms")

	path := RootPersist + "/"
	files, err := ioutil.ReadDir(path)
	if err != nil {
		logger.GetLogger().Error("Failed to read dir", logfields.Error, err, "path", path)
		return
	}

	for _, file := range files {
		filename := file.Name()
		logger.GetLogger().Debug("filename", "filename", filename)
		if !file.IsDir() && strings.HasSuffix(filename, "rpm") {
			fname := path + filename
			logger.GetLogger().Debug("Removing", "filename", fname)
			if err := os.Remove(fname); err != nil {
				logger.GetLogger().Error("Failed to remove", logfields.Error, err)
			}
		}
	}
}

func (n *Nxos) GetServiceIp() string {
	n.RLock()
	defer n.RUnlock()

	return n.ServiceIp
}

func (n *Nxos) calcDpuPortRange(dpu uint16) string {
	portCount := (n.DpuPortHigh - n.DpuPortLow + 1) / n.NumDpu
	index := dpu - 1
	portLow := n.DpuPortLow + portCount*index
	portHigh := n.DpuPortLow + portCount*(index+1) - 1
	return fmt.Sprintf("%d-%d", portLow, portHigh)
}
