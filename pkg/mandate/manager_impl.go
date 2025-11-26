// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package mandate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/tracingpolicy"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"

	"github.com/isovalent/hubble-fgs/pkg/alerts"
	"github.com/isovalent/hubble-fgs/pkg/attempt"
	mandateconf "github.com/isovalent/hubble-fgs/pkg/mandate/conf"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"
)

// manager implements the Manager interface
type manager struct {
	obj            *Obj
	cnf            mandateconf.ManagerConf
	sensorMgr      SensorManager
	alertRuleMgr   AlertRuleManager
	c              chan cmd
	wg             sync.WaitGroup
	loadedPolicies []policy
	attLog         attempt.Log
	polNextID      uint
}

type cmdID int

const (
	refreshCmdID cmdID = iota
	stopCmdID
	statusCmdID
	configureCmdID
)

type statusRet struct {
	ret chan *Status
}

type cmd struct {
	id cmdID
	// only set if id == statusCmdID
	status *statusRet
	// only set if id = configureCmdID
	confArg *ConfArg
}

var (
	refreshCmd = cmd{id: refreshCmdID}
	stopCmd    = cmd{id: stopCmdID}
)

type polTy int

const (
	invalidPolTy polTy = iota
	tracingPolTy
	alertPolTy
)

type policy struct {
	namespace string
	name      string
	origName  string
	url       string
	ty        polTy
	checksum  []byte
	mode      string
}

func invalidPolicy() policy {
	return policy{ty: invalidPolTy}
}

func newTracingPolicy(url string, tp tracingpolicy.TracingPolicy, mode string) policy {
	ret := policy{
		url:       url,
		namespace: tpNs(tp),
		name:      tp.TpName(),
		ty:        tracingPolTy,
		mode:      mode,
	}

	ret.origName = ret.name
	if oname, ok := OrigPolName(ret.name); ok {
		ret.origName = oname
	}
	return ret
}

// NewManager creates a new manager
//
//revive:disable:unexported-return
func NewManager(
	cnf mandateconf.ManagerConf,
	sensorMgr SensorManager,
	alertRuleMgr AlertRuleManager,
) (*manager, error) {
	mgr := &manager{
		cnf:          cnf,
		sensorMgr:    sensorMgr,
		alertRuleMgr: alertRuleMgr,
		polNextID:    1,
	}
	return mgr, nil
}

func (m *manager) unloadPolicy(ctx context.Context, pol policy) error {
	switch pol.ty {
	case tracingPolTy:
		return m.sensorMgr.DeleteTracingPolicy(ctx, pol.name, pol.namespace)
	case alertPolTy:
		if m.alertRuleMgr == nil {
			return errors.New("alert manager disabled")
		}
		m.alertRuleMgr.DeleteAlertRule(pol.name)
		return nil
	default:
		return fmt.Errorf("unknown policy type: %d", pol.ty)
	}
}

func (m *manager) attemptLoadPolicy(
	ctx context.Context,
	att *attempt.InprAttempt,
	pol *Policy,
	data []byte,
) (policy, error) {
	var unstr unstructured.Unstructured
	if err := yaml.UnmarshalStrict([]byte(data), &unstr); err != nil {
		return invalidPolicy(), fmt.Errorf("failed to unmarshal YAML: %w", err)
	}

	switch unstr.GetKind() {
	case "TracingPolicy":
		mp, err := m.attemptLoadMandateTracingPolicy(ctx, att, data, pol.mode_)
		if err != nil {
			return invalidPolicy(), err
		}
		return newTracingPolicy(pol.url_.String(), mp, pol.mode_), nil
	case "TracingPolicyNamespaced":
		return invalidPolicy(), errors.New("namespaced tracing policies are not supported")
	case "AlertRule":
		return m.attemptLoadAlert(att, data, pol)
	default:
		return invalidPolicy(), errors.New("unknown policy")

	}
}

func (m *manager) refresh(ctx context.Context) {
	refrAtt := m.attLog.NewAttempt("refresh")
	var err error
	var obj *Obj
	var data []byte
	defer func() {
		err := refrAtt.Complete(err)
		if err != nil {
			logger.GetLogger().Warn("mandate: attempt did not properly completed", logfields.Error, err)
		}
	}()

	refrAtt = refrAtt.WithInfo("url", m.cnf.URL)
	fetchAtt := refrAtt.NewAttempt("fetch mandate").WithInfo("url", m.cnf.URL)
	obj, data, err = fetchMandateObj(m.cnf.URL)
	fetchAtt.Complete(err)
	if err != nil {
		return
	}

	if m.obj != nil && m.obj.SameVersion(obj) {
		refrAtt = refrAtt.WithInfo("skipped", "true")
		return
	}

	// now that we know that the mandate is meant to be loaded, calculate its hash
	h := sha256.New()
	h.Write(data)
	obj.sha256 = h.Sum(nil)

	refrAtt = refrAtt.WithInfo("checksum", obj.Checksum())
	if ver, ok := obj.Version(); ok {
		refrAtt = refrAtt.WithInfo("version", ver)
	}

	var unloadMandateID string

	res, err := m.fetchAndLoadPolicies(ctx, refrAtt, obj)
	if err == nil {
		// success, unload existing policies (of old mandate)
		if m.obj != nil {
			unloadMandateID = m.obj.id()
		}
		// and replace object and loaded policy lists
		m.obj = obj
		m.loadedPolicies = res.loadedPolicies
		m.obj.loadedTime = time.Now()
	} else {
		// failure, unload new policies
		unloadMandateID = obj.id()
	}

	for _, pol := range res.unloadPolicies {
		attempt.RunAttempt(
			refrAtt.NewAttempt("unload policy").WithInfo("policy", pol.origName).WithInfo("mandate", unloadMandateID),
			func() error {
				err := m.unloadPolicy(ctx, pol)
				if err != nil {
					logger.GetLogger().Warn("failed to unload mandate policy", "policy", pol.name, logfields.Error, err)
				}
				return err
			})
	}
}

type fetchLoadPoliciesResult struct {
	loadedPolicies []policy
	unloadPolicies []policy
}

// fetchAndLoadPolicies fetches and loads the policies in obj
// It returns an error if something went wrong, plus a structure that holds
// the list of policies to be unloaded.
// If everything goes well, it returns list of loaded policies, and the list of policies to be unloaded.
func (m *manager) fetchAndLoadPolicies(ctx context.Context, refrAtt *attempt.InprAttempt, obj *Obj) (*fetchLoadPoliciesResult, error) {
	res := &fetchLoadPoliciesResult{}
	policyData := make([]policyData, len(obj.Mandate.Policies))

	// first pass, attempt to fetch all the policies
	// NB: we want to make sure that all policies are fetchable before starting loading them.
	// If at least one policy cannot be fetched, return an error
	for i := range obj.Mandate.Policies {
		pol := &obj.Mandate.Policies[i]
		data, err := attemptFetchURL(refrAtt.NewAttempt("fetch policy"), pol.url_)
		if err != nil {
			return nil, err
		}
		policyData[i] = data
	}

	// second pass, attempt to load them.
	// before loading them, check that no existing loaded policy
	// share same sha256sum; in case, skip the load of the policy.

	// Policies whose load has been skipped
	skippedPolicies := make([]policy, 0)
	// Policies loaded right now
	loadedPolicies := make([]policy, 0, len(obj.Mandate.Policies))
	// We keep the unloadedPolicies as a full copy of m.loadedPolicies,
	// because in case of error, we shall not change m.loadedPolicies.
	unloadedPolicies := make([]policy, len(m.loadedPolicies))
	copy(unloadedPolicies, m.loadedPolicies)

	h := sha256.New()

	for i := range obj.Mandate.Policies {
		pol := &obj.Mandate.Policies[i]
		data := policyData[i]

		// Compute the policyData checksum against loaded policies to check
		// if same policy is already loaded with same policy mode.
		h.Reset()
		h.Write(data)
		checksum := h.Sum(nil)
		idx := slices.IndexFunc(unloadedPolicies, func(p policy) bool {
			return bytes.Equal(p.checksum, checksum) && p.mode == pol.mode_
		})

		skipLoad := idx != -1
		if skipLoad {
			loadedPol := unloadedPolicies[idx]
			logger.GetLogger().Info("mandate: skipping already loaded policy", "url", pol.url_.String())
			// Update policy url in case it changed
			loadedPol.url = pol.url_.String()
			// Remove this policy from the to-be-unloaded set and add it to the skipped set
			unloadedPolicies = append(unloadedPolicies[:idx], unloadedPolicies[idx+1:]...)
			skippedPolicies = append(skippedPolicies, loadedPol)
		} else {
			loadAtt := refrAtt.NewAttempt("load policy").WithInfo("url", pol.url_.String())
			loadedPol, err := m.attemptLoadPolicy(ctx, loadAtt, pol, data)
			if err != nil {
				// Return policies currently loaded as to-be-unloaded
				res.unloadPolicies = loadedPolicies
				return res, fmt.Errorf("failed to load policy %q: %w", pol.url_, err)
			}
			// set the policy checksum and add it to the loaded set
			loadedPol.checksum = checksum
			loadedPolicies = append(loadedPolicies, loadedPol)
		}
	}

	// Everything went well, loadedPolicies will be the sum of
	// actually loaded ones + skipped ones
	res.loadedPolicies = slices.Concat(loadedPolicies, skippedPolicies)
	// Remaining elems in unloadPolicies (if any) need to be unloaded
	res.unloadPolicies = unloadedPolicies
	return res, nil
}

// attemptLoadMandateTracingPolicy attempts to load a mandate policy
func (m *manager) attemptLoadMandateTracingPolicy(
	ctx context.Context,
	att *attempt.InprAttempt,
	data []byte,
	mode string,
) (tracingpolicy.TracingPolicy, error) {
	var ret tracingpolicy.TracingPolicy
	var err error
	defer func() {
		att.Complete(err)
	}()

	// apply mode if it is set
	if mode != "" {
		data, err = tracingpolicy.PolicyYAMLSetMode(data, mode)
		if err != nil {
			return nil, err
		}
		att = att.WithInfo("mode", mode)
	}

	ret, err = tracingpolicy.TPContext.FromYAML(string(data))
	if err != nil {
		return nil, err
	}
	att.SetInfo("name", ret.TpName())

	// wrap the policy so that it can have a unique name based on the object id
	ret = m.NewMandatePolicy(ret)
	err = m.sensorMgr.AddTracingPolicy(ctx, ret)
	if err != nil {
		// NB: In certain situations, the sensor manager will fail to load a policy, but it
		// will keep it under the load_error state. So, let's try to remove it here to not
		// leave any leftovers
		m.sensorMgr.DeleteTracingPolicy(ctx, ret.TpName(), "")
		return nil, err
	}
	return ret, nil
}

func (m *manager) uniqueAlertName(ar *v1alpha1.AlertRule) string {
	name := mandateAlertName(ar.GetName(), m.polNextID)
	m.polNextID++
	return name
}

func (m *manager) attemptLoadAlert(
	att *attempt.InprAttempt,
	data []byte,
	mandatePol *Policy,
) (pol policy, err error) {
	pol = invalidPolicy()
	defer func() {
		att.Complete(err)
	}()

	if m.alertRuleMgr == nil {
		err = errors.New("alerts disabled")
		return
	}

	if mandatePol.ownMode() != "" {
		err = errors.New("alerts do not support mode")
		return
	}

	var ar *v1alpha1.AlertRule
	crdCtx, err := alerts.CRDContext()
	if err != nil {
		err = fmt.Errorf("failed to retrieve CRD context for AlertRule: %w", err)
		return
	}
	ar, err = crdCtx.FromYAML(string(data))
	if err != nil {
		return
	}

	// NB(kkourt): We rename the alert rules so that alerts with the same name end up having
	// different names as we do for policies. This allows us to ensure that everything loads
	// properly before removing the policies from the previous mandate file
	pol = policy{
		name:     m.uniqueAlertName(ar),
		origName: ar.GetName(),
		url:      mandatePol.url_.String(),
		ty:       alertPolTy,
	}
	ar.SetName(pol.name)
	// Force-set the origName log file if needed.
	if ar.Spec.Export.Filename == "" {
		ar.Spec.Export.Filename = pol.origName + ".log"
	}
	err = m.alertRuleMgr.AddAlertRule(ar)
	if err != nil {
		err = fmt.Errorf("failed to add alert rule: %w", err)
		return
	}

	return
}

func (m *manager) start() {
	defer m.wg.Done()
	ctx := context.Background()
	m.refresh(ctx)
	timer := time.NewTimer(m.cnf.RefreshPeriod)
	for {
		// wait for a new command, or the timer to expire
		var cmd cmd
		timer.Reset(m.cnf.RefreshPeriod)
		select {
		case cmd = <-m.c:
		case <-timer.C:
			cmd = refreshCmd
		}

		// execute command
		switch cmd.id {
		case refreshCmdID:
			m.refresh(ctx)
		case statusCmdID:
			cmd.status.ret <- m.status()
		case configureCmdID:
			m.configure(ctx, cmd.confArg)
		case stopCmdID:
			return
		}
	}
}

func (m *manager) status() *Status {
	var ret Status
	ret.Running = true
	ret.Conf = m.cnf
	if m.obj != nil {
		ret.Mandate = &LoadedMandate{
			Version:  m.obj.VersionOrEmpty(),
			LoadedAt: m.obj.loadedTime,
			Checksum: m.obj.Checksum(),
		}
	}
	ret.Log = m.attLog.Attempts()

	return &ret
}

func (m *manager) Start() error {
	if m.c != nil {
		return fmt.Errorf("manager has already started")
	}

	m.c = make(chan cmd)
	m.wg = sync.WaitGroup{}
	m.wg.Add(1)
	go m.start()
	return nil
}

func (m *manager) Refresh() {
	m.c <- refreshCmd
}

func (m *manager) stop() error {
	if m.c == nil {
		return fmt.Errorf("manager has not started")
	}
	m.c <- stopCmd
	return nil
}

func (m *manager) Stop() error {
	if err := m.stop(); err != nil {
		return err
	}
	m.wg.Wait()
	m.c = nil
	return nil
}

func (m *manager) Status() *Status {
	if m.c == nil {
		return &Status{
			Conf:    m.cnf,
			Running: false,
		}
	}
	statusCmd := cmd{
		id: statusCmdID,
		status: &statusRet{
			ret: make(chan *Status),
		},
	}
	m.c <- statusCmd
	return <-statusCmd.status.ret
}

func (m *manager) Configure(arg ConfArg) error {
	if m.c == nil {
		return errors.New("mandate manager not running")
	}
	confCmd := cmd{
		id:      configureCmdID,
		confArg: &arg,
	}
	m.c <- confCmd
	return nil
}

func (m *manager) configure(ctx context.Context, arg *ConfArg) {
	if arg.URL != nil {
		m.cnf.URL = *arg.URL
	}

	if arg.RefreshPeriod != nil {
		m.cnf.RefreshPeriod = *arg.RefreshPeriod
	}

	if arg.Refresh {
		m.refresh(ctx)
	}
}
