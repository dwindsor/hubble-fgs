package dataplane

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"time"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"

	dpAppPolicy "github.com/isovalent/hubble-fgs/pkg/dpu/policy"
	"github.com/isovalent/hubble-fgs/pkg/dpu/socket"
	dpuPolicy "github.com/isovalent/hubble-fgs/pkg/model/server/dpu"
	"github.com/isovalent/hubble-fgs/pkg/utils"
)

// Returns a newly created accelerated dataplane object
//
// Parameters:
//   - id: string
//   - apiPath: string
//   - persistPath: string
func NewAcceleratedDataplane(id, apiPath, persistPath string) *AcceleratedDataplane {
	return &AcceleratedDataplane{
		Accelerated: &AcceleratedDataplaneProcess{
			Id:          id,
			ApiPath:     apiPath,
			PersistPath: persistPath,
		},
	}
}

// -----------------------------------------------------------------------------
// Individual Dataplane Implementation
// -----------------------------------------------------------------------------

type AcceleratedDataplaneProcess struct {
	Id          string
	ApiPath     string
	PersistPath string
	Version     string
	ServicePath string
	WatchPath   string
	Status      atomic.Bool

	PolicyList []dpAppPolicy.FwPolicyV2 `json:"policy_list"`
}

func (dp *AcceleratedDataplaneProcess) GetId() string {
	return dp.Id
}

func (dp *AcceleratedDataplaneProcess) Start(ctx context.Context) error {
	// Setting status to true
	dp.Status.Store(true)

	// Loading policies
	err := dp.LoadFirewallPolicies(ctx, dp.PersistPath)
	if err != nil {
		logger.GetLogger().Error("Failed to load policies from file for dataplane", logfields.Error, err)
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

func (dp *AcceleratedDataplaneProcess) StoreFirewallPolicies(ctx context.Context, path string) error {
	// Creating file object
	policyFile := &PolicyFile{
		PolicyList: dp.PolicyList,
	}

	// Persisting policies in the dataplane
	err := utils.StoreJsonFile(ctx, path, policyFile, 0644)
	if err != nil {
		logger.GetLogger().Error("Failed to persist policies for dataplane", logfields.Error, err)
		return err
	}
	logger.GetLogger().Debug("Dataplane policies persisted", "path", path)
	return nil
}

/* This is a nop function stubbed out here from hs-nep until its actually used */
func calculateHash(policies []dpAppPolicy.FwPolicyV2) string {
	// Creating an array of policy IDs
	ids := []string{}
	for _, p := range policies {
		ids = append(ids, p.Id)
	}

	// Calculating hash
	// Hash = Policies Sorted by ID Ascending then MD5 all the IDs concatenated together
	slices.SortFunc(ids, func(a, b string) int {
		return cmp.Compare(a, b)
	})
	var idsString string
	for _, id := range ids {
		idsString += id
	}
	hash := sha256.Sum256([]byte(idsString))
	return hex.EncodeToString(hash[:])
}

func (dp *AcceleratedDataplaneProcess) LoadFirewallPolicies(ctx context.Context, path string) error {
	// Loading policies from the dataplane
	policyFile := &PolicyFile{}
	err := utils.LoadJsonFile(ctx, path, policyFile)
	if err != nil {
		if os.IsNotExist(err) {
			logger.GetLogger().Debug("no policy file found for dataplane")
			policyMsg := &dpAppPolicy.FwPolicyMsgV2{
				Hash:         calculateHash([]dpAppPolicy.FwPolicyV2{}),
				Verification: false,
				Policies:     []dpAppPolicy.FwPolicyV2{},
			}
			updateErr := dp.UpdateFirewallPolicies(ctx, policyMsg)
			if updateErr != nil {
				logger.GetLogger().Error("failed to apply empty policies to dataplane")
				return errors.Join(err, updateErr)
			}
			return nil
		}
		logger.GetLogger().Error("failed to load policies for dataplane", logfields.Error, err)
		return err
	}
	logger.GetLogger().Debug("Dataplane policies loaded", "path", path)

	// Updating policies in dataplane object
	policyMsg := &dpAppPolicy.FwPolicyMsgV2{
		Hash:         calculateHash([]dpAppPolicy.FwPolicyV2{}),
		Verification: false,
		Policies:     policyFile.PolicyList,
	}
	err = dp.UpdateFirewallPolicies(ctx, policyMsg)
	if err != nil {
		logger.GetLogger().Error("Failed to apply loaded policies to dataplane", logfields.Error, err)
		return err
	}

	return nil
}

// -----------------------------------------------------------------------------
// Accelerated Dataplane Implementation
// -----------------------------------------------------------------------------

type AcceleratedDataplane struct {
	Accelerated *AcceleratedDataplaneProcess
}

func (dp *AcceleratedDataplane) Mode() DataplaneType {
	return ACCELERATED
}

func (dp *AcceleratedDataplane) Version() string {
	return dp.Accelerated.Version
}

func (dp *AcceleratedDataplane) ApiPath() string {
	return dp.Accelerated.ApiPath
}

func (dp *AcceleratedDataplane) PolicyList() []dpAppPolicy.FwPolicyV2 {
	return dp.Accelerated.PolicyList
}

func (dp *AcceleratedDataplane) PushPolicy(ctx context.Context, policies []*dpuPolicy.DPUPolicyRule) error {
	fwPolicy := dpAppPolicy.DPURuleToJSON(policies)

	// Creating policy message
	policyMsg := &dpAppPolicy.FwPolicyMsgV2{
		Hash:         calculateHash([]dpAppPolicy.FwPolicyV2{}),
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

func (dp *AcceleratedDataplane) RemovePolicy(ctx context.Context) error {
	// Creating policy message
	policyMsg := &dpAppPolicy.FwPolicyMsgV2{
		Hash:         calculateHash([]dpAppPolicy.FwPolicyV2{}),
		Verification: false,
		Policies:     []dpAppPolicy.FwPolicyV2{},
	}

	// Applying policy to the accelerated dataplane
	err := dp.Accelerated.UpdateFirewallPolicies(ctx, policyMsg)
	if err != nil {
		logger.GetLogger().Error("Failed to remove policy to accelerated dataplane", logfields.Error, err)
		return err
	}
	return nil
}

func (dp *AcceleratedDataplane) Init(_ context.Context, acceleratedServicePath string, _ string) error {
	dp.Accelerated.ServicePath = acceleratedServicePath
	dp.Accelerated.WatchPath = filepath.Join(dp.Accelerated.ServicePath, FIFODIR)

	return nil
}

func (dp *AcceleratedDataplane) Connect(ctx context.Context, acceleratedServicePath string, _ bool) error {
	// Initializing dataplane
	err := dp.Init(ctx, acceleratedServicePath, "")
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
	dp.Accelerated.StoreFirewallPolicies(ctx, dp.Accelerated.PersistPath)
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
