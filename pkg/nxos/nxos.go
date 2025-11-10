package nxos

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"io/ioutil"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
	"golang.org/x/sync/errgroup"

	"github.com/isovalent/hubble-fgs/pkg/config/library"
	"github.com/isovalent/hubble-fgs/pkg/model/server/dpu"
	"github.com/isovalent/hubble-fgs/pkg/model/switchpolicy"
	model "github.com/isovalent/hubble-fgs/pkg/nxosmodel"
	"github.com/isovalent/hubble-fgs/pkg/token"

	"github.com/openconfig/gnmic/pkg/api"
	"github.com/openconfig/ygot/ytypes"
	"github.com/spf13/viper"
	"golang.design/x/chann"
)

const (
	svcInst = "System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]"
	seqNum  = 10

	TokenFile             = "/iox_data/k8sauth_token"
	waitForDpuInterval    = 10  // in second
	waitForInSyncInterval = 30  // in second
	notifTimeout          = 900 // in second

	dpuStatusCheckTimer = 1 // in second
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
	err = n.getAdmissionAndConnectionStates(ctx)
	if err != nil {
		return err
	}

	// get proxy config
	err = n.getProxyConfig(ctx)
	if err != nil {
		return err
	}

	// get model and nxos version
	err = n.getModelAndVersion(ctx)
	if err != nil {
		return err
	}

	// get Serial number.
	err = n.getSerialNum(ctx)
	if err != nil {
		return err
	}

	n.Stage = StageEnable
	n.Wait = chann.New[string]()
	n.WaitHa = chann.New[string]()
	n.GidsInUse = make(map[uint16]string)
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
	n.LbMode = model.Cisco_NX_OSDevice_Sas_LbModeType_symmetric_hash
	n.Ha.Peers = make(map[string]HaPeer)
	n.Ha.Adjacencies = make(map[string]HaAdj)
	n.Ha.Members = make(map[string]HaMbr)
	n.Ha.Alloc = make(map[string]HaAlloc)
	n.Ha.FlowSync = make(map[string]bool)
	n.Ha.Local.Criteria = make(map[HaCrit]bool)
	if n.SkipDpu {
		n.Ha.Local.Criteria[HaCritDpuHealth] = true
		n.Ha.Local.Criteria[HaCritDpuInSync] = true
	} else {
		n.Ha.Local.Criteria[HaCritDpuHealth] = false
		n.Ha.Local.Criteria[HaCritDpuInSync] = false
	}
	n.Ha.Local.Criteria[HaCritSvcRedir] = false
	// HACK: set to true until integration with new policy
	n.Ha.Local.Criteria[HaCritPolicy] = true
	n.Ha.Partners = make(map[string]struct{})
	n.Ha.IsLeader = true

	n.haInit(ctx)
	go n.haSetup(ctx)

	return nil
}

// GetHeadlessMode checks if the agent should run in "headless mode", which means operating without a controller.
// It reads the configuration from /etc/sas.cfg and sets SkipCtrlr accordingly.
func (n *Nxos) GetHeadlessMode() bool {
	n.SkipCtrlr = false

	// read headless mode from config file
	viper.SetConfigFile("/etc/sas.cfg")
	viper.SetConfigType("env")
	err := viper.ReadInConfig()
	if err != nil {
		logger.GetLogger().Error("ReadInConfig fails", logfields.Error, err)
		return n.SkipCtrlr
	}

	sc := viper.GetString("NX_AGENT_HEADLESS_MODE")
	if sc == "1" {
		logger.GetLogger().Info("Headless mode set")
		n.SkipCtrlr = true
	}
	return n.SkipCtrlr
}

// GetSerialNum attempts to retrieve the serial number; returns an empty string on error.
func (n *Nxos) GetSerialNum(ctx context.Context) string {
	if err := n.getSerialNum(ctx); err != nil {
		logger.GetLogger().Error("Failed to get serial number", logfields.Error, err)
		return ""
	}
	return n.SerNum
}

// CheckUpgradeState checks if the container is currently in an upgrade state.
// It retrieves the agent upgrade state and determines if an upgrade is in progress.
func (n *Nxos) CheckUpgradeState(ctx context.Context) (bool, error) {
	agentUpgradeState, err := n.getAgentUpgradeState(ctx)
	if err != nil || agentUpgradeState == model.Cisco_NX_OSDevice_SasAgentUpgradeStateE_UNSET {
		logger.GetLogger().Debug("agent upgrade state is not in upgrade_in_progress")
		return false, err
	}
	return agentUpgradeState == model.Cisco_NX_OSDevice_SasAgentUpgradeStateE_upgrade_in_progress, nil
}

// Cleanup performs graceful shutdown cleanup
func (n *Nxos) Cleanup(ctx context.Context) error {
	n.RLock()
	defer n.RUnlock()
	n.cleanup(ctx)
	return nil
}

// Close performs final resource cleanup
func (n *Nxos) Close(ctx context.Context) error {
	n.GnmiClose(ctx)
	return nil
}

// GetExitCodeForSignal returns the appropriate exit code based on the received signal and upgrade state.
//
// Behavior:
//   - During upgrade: Always returns 201 to prevent restart regardless of signal
//   - SIGTERM: Returns 201 to terminate without restart
//   - SIGINT: Returns 200 to allow restart
//   - Default: Returns 200 to allow restart
func (n *Nxos) GetExitCodeForSignal(sig os.Signal, inUpgrade bool) int {
	if inUpgrade || sig == syscall.SIGTERM {
		// During upgrade, never restart regardless of signal
		return 201
	}

	// Normal operation
	if sig == syscall.SIGINT {
		// Manual interrupt - allow restart for debugging
		return 200
	}
	// Default - restart
	return 200
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

func (n *Nxos) isConfigured(_ context.Context, isLock bool) bool {

	if isLock {
		n.RLock()
		defer n.RUnlock()
	}

	c := n.Configured
	logger.GetLogger().Debug("Configured:", "", c)
	return c
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
		n.Stage = StageVrf
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
		case <-ctx.Done():
			logger.GetLogger().Info("Aborting wait for DPU.")
			return 0, fmt.Errorf("no DPUs discovered")
		case wait := <-n.Wait.Out():
			logger.GetLogger().Debug("Waked up", "time", wait)
			num, ok := n.isAllDpuCounted(ctx)
			if ok {
				return num, nil
			}
		}
	}
}

func (n *Nxos) checkDPUVersion(status []dpu.DPUReportStatus) error {
	var err error

	if n.Update.Persist.Id == "" {
		return nil
	}

	n.Update.HasRes = true
	for _, s := range status {
		// The NA is a NXOS bug workaround. Once fixed (is it fixed) we can remove.
		if n.Update.Persist.Version != s.DpVersion && s.DpVersion != "NA" {
			logger.GetLogger().Debug("persisted version does not match dpu version", "persistent", n.Update.Persist.Version, "dpuVersion", s.DpVersion)
			n.Update.Result.ErrCode = int(1)
			n.Update.Result.ErrMsg = "Not running updated DPU firmware"
			err = fmt.Errorf("NXOS expected '%s' DPU version '%s' mismatch", n.Update.Persist.Version, s.DpVersion)
			break
		}
	}
	if n.Update.Result.ErrMsg == "" {
		n.Update.Result.Success = true
	}
	return err
}

func (n *Nxos) waitForDpuAgent(ctx context.Context, expected int) error {
	// If skipDpu is set, skip DPU agent check and return immediately.
	if n.SkipDpu {
		logger.GetLogger().Info("SkipDpu is true, skipping DPU agent check")
		return nil
	}
	currTimer := dpuStatusCheckTimer * time.Second
	maxDPUAgentBackoff := 10 * time.Second

	for {
		select {
		case <-ctx.Done():
			logger.GetLogger().Info("Aborting, DPU status check")
			return fmt.Errorf("no DPU agents found")
		// linear backoff up to 10s, we really do want this to connect to
		// the DPUs otherwise our firewall is unhealthy.
		case <-time.After(currTimer):
			status, err := n.dpuListener.GetDPUStatus()
			if err != nil || len(status) != expected {
				if currTimer < maxDPUAgentBackoff {
					currTimer = currTimer + time.Second
				}
				logger.GetLogger().Warn("Waiting for DPUs to connect", "expected", expected, "online", len(status))
				continue
			}
			logger.GetLogger().Info("Discovered DPU agents", "count", len(status))

			err = n.checkDPUVersion(status)
			if err != nil {
				logger.GetLogger().Warn("Incorrect DPU version", logfields.Error, err)
			}

			return nil
		}
	}
}

func (n *Nxos) isTokenAvail(_ context.Context) bool {
	n.RLock()
	defer n.RUnlock()

	return n.Ctrlr.Token != ""
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

func (n *Nxos) setFwPolicyStateAll(ctx context.Context, isLock bool) error {

	if isLock {
		n.RLock()
		defer n.RUnlock()
	}

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
	if n.Stage != StageVrf && n.Stage != StageNormal {
		logger.GetLogger().Debug("Skip service redir prog:", "stage", n.Stage)
		return nil
	}

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

func (n *Nxos) Setup(ctx context.Context, cancel context.CancelFunc, low, high uint16, dpuListener *dpu.DPUListener, policyHandler switchpolicy.PolicyHandler) error {

	n.DpuPortLow = low
	n.DpuPortHigh = high
	n.dpuListener = dpuListener
	n.policyHandler = policyHandler

	// set the cancel function for any nxos initiated context cancellation
	// to other goroutines
	n.cancel = cancel

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

	// DPU inventory-done pending
	n.Agent.SystemState |= SysStDpuPending
	err = n.setSystemState(ctx)
	if err != nil {
		logger.GetLogger().Error("Fail to set system state", logfields.Error, err)
	}

	dpuCnt, err := n.waitForDpu(ctx)
	if err != nil {
		logger.GetLogger().Error("Fail to wait for dpu", logfields.Error, err)
		return err
	}

	err = n.waitForDpuAgent(ctx, int(dpuCnt))
	if err != nil {
		logger.GetLogger().Error("Failed to connect to dpu Agent", logfields.Error, err)
		return err
	}

	now := time.Now().Unix()
	elapsed := now - n.Ha.Start
	logger.GetLogger().Debug("time elapsed since HA starts: ", "time", elapsed)
	if !n.Ha.IsLeader && elapsed < 2*haTimeout {
		wait := 2*haTimeout - elapsed
		logger.GetLogger().Debug("wait before service redir prog ", "seconds", wait)
		time.Sleep(time.Duration(wait) * time.Second)
	}

	go n.checkNotif(ctx)
	go n.setup(ctx, dpuCnt)

	logger.GetLogger().Info("NXOS setup complete")
	return nil
}

// GetToken returns the Kubernetes controller authentication token.
func (n *Nxos) GetToken() string {
	return n.Ctrlr.Token
}

// SetToken parses and sets the Kubernetes controller authentication token.
// If the token is different from the existing one, it persists the new token
// and indicates if agw restart is needed.
func (n *Nxos) SetToken(ctx context.Context, k8sToken string) (bool, error) {
	logger.GetLogger().Info("parsing and setting K8s auth token")
	restartNeeded := false

	agentToken := token.GetAgentToken()
	if agentToken == nil {
		return restartNeeded, fmt.Errorf("AgentToken instance is nil")
	}
	// If provided token is same as existing token, no action needed.
	prev := n.Ctrlr.Token
	if prev == k8sToken {
		logger.GetLogger().Debug("K8s auth token is unchanged")
		return restartNeeded, nil
	}
	// If different token, validate the provided token.
	if err := agentToken.ValidK8sAuth(k8sToken); err != nil {
		return restartNeeded, err
	}
	// Persist the token.
	if err := agentToken.SetAndPersistK8sAuthToken(k8sToken); err != nil {
		return restartNeeded, err
	}
	// Set the environment variable for the token.
	if err := os.Setenv(envToken, k8sToken); err != nil {
		return restartNeeded, fmt.Errorf("fail to set K8s token to env: %w", err)
	}
	// Set the token in the Nxos struct.
	n.Ctrlr.Token = k8sToken
	logger.GetLogger().Debug("K8s auth token is set")
	// Only set restartNeeded to true, if everything above succeeded.
	if prev != "" {
		// If previous token is empty, it means token is set for the first time,
		//  where no restart is needed.
		// If previous token is not empty and different, restart is needed to
		//  pick up the new token.
		logger.GetLogger().Info("K8s auth token changed, restart needed")
		restartNeeded = true
	}
	return restartNeeded, nil
}

func (n *Nxos) GracefulRestartAgent(ctx context.Context, cleanup bool) {
	logger.GetLogger().Info("restarting agw agent...")
	if cleanup {
		// Cleanup service redirects before exit.
		n.cleanup(ctx)
		logger.GetLogger().Debug("Graceful restart with cleanup")
	}
	// send cancel to all goroutines, and wait on waitGroups to complete.
	n.cancel()
	waitGroup, _ := errgroup.WithContext(ctx)
	if err := waitGroup.Wait(); err != nil {
		logger.GetLogger().Error("Error waiting for goroutines", logfields.Error, err)
	}
	// Close Nxos gNMI connection.
	n.GnmiClose(ctx)
	// As per init.sh script, exiting with code 200 will cause the agent to restart.
	os.Exit(200)
}

func (n *Nxos) setup(ctx context.Context, dpuCnt uint16) {

	logger.GetLogger().Debug("Waiting for DPU in sync")
	if !n.SkipDpu {
		for {
			time.Sleep(waitForInSyncInterval * time.Second)
			n.RLock()

			logger.GetLogger().Debug("Check for DPU InSync")

			inSync := n.Ha.Local.Criteria[HaCritDpuInSync]
			if inSync {
				logger.GetLogger().Debug("DPU InSync")
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
	err = n.setFwPolicyStateAll(ctx, true)
	if err != nil {
		logger.GetLogger().Error("Fail to set fw policy state", logfields.Error, err)
		return
	}
	logger.GetLogger().Info("VRF pinning ready")

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

	if n.isConfigured(ctx, false) && !n.IsDelSvcFw {
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

	n.AllocPrev.Next = 0
	n.AllocPrev.Gids = make(map[string]uint16)
	n.AllocPrev.VrfDpus = make(map[string]uint16)
	n.AllocPrev.BdDpus = make(map[string]uint16)
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

func haveToken(_ context.Context) bool {

	finfo, err := os.Stat(TokenFile)
	if err != nil {
		logger.GetLogger().Error("fail to stat token file", logfields.Error, err,
			"file", TokenFile)
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
	return n.serviceIp
}

func (n *Nxos) SetServiceIp(ip string) {
	// Setting ServiceIp locally
	n.serviceIp = ip

	// Updating service ip in the dpu config
	var dpuConfig v1alpha.DpuConfig
	err := library.GetRepository().GetConfig(v1alpha.ConfigType_CONFIG_TYPE_DPU, &dpuConfig)
	if err != nil && !library.IsConfigNotFound(err) {
		logger.GetLogger().Error("Failed to get dpu config", "error", err)
	}
	dpuConfig.ServiceIp = ip
	configObj := &v1alpha.ConfigObject{
		Type:   v1alpha.ConfigType_CONFIG_TYPE_DPU,
		Source: v1alpha.ConfigSource_CONFIG_SOURCE_LOCAL,
		Config: &v1alpha.ConfigObject_ConfigDpu{ConfigDpu: &dpuConfig},
	}
	library.GetRepository().AddConfig(configObj)
}

func (n *Nxos) calcDpuPortRange(dpu uint16) string {
	portCount := (n.DpuPortHigh - n.DpuPortLow + 1) / n.NumDpu
	index := dpu - 1
	portLow := n.DpuPortLow + portCount*index
	portHigh := n.DpuPortLow + portCount*(index+1) - 1
	return fmt.Sprintf("%d-%d", portLow, portHigh)
}

func DpuInSync(ctx context.Context, inSync bool) {
	logger.GetLogger().Debug("DpuInSync")

	Nexus.Lock()
	defer Nexus.Unlock()

	if Nexus.Ha.Local.Criteria != nil {
		Nexus.haUpdateCrit(ctx, HaCritDpuInSync, inSync)
	}
}

func DpuHealth(ctx context.Context, healthy bool, count int) {
	logger.GetLogger().Debug("DpuHealth", "ok", healthy, "count", count)

	Nexus.Lock()
	defer Nexus.Unlock()

	if healthy && count == int(Nexus.NumDpu) && Nexus.Ha.Local.Criteria != nil {
		Nexus.haUpdateCrit(ctx, HaCritDpuInSync, true)
	} else if Nexus.Ha.Local.Criteria != nil {
		Nexus.haUpdateCrit(ctx, HaCritDpuInSync, false)
	}
}
