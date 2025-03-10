//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package mandate

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"time"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/isovalent/hubble-fgs/pkg/attempt"
)

// manager implements the Manager interface
type manager struct {
	obj            *Obj
	cnf            ManagerConf
	sensorMgr      SensorManager
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
)

type statusRet struct {
	ret chan *Status
}

type cmd struct {
	id cmdID
	// only set if id == statusCmdID
	status *statusRet
}

var (
	refreshCmd = cmd{id: refreshCmdID}
	stopCmd    = cmd{id: stopCmdID}
)

type policy struct {
	namespace string
	name      string
}

func newPolicy(tp tracingpolicy.TracingPolicy) policy {
	return policy{
		namespace: tpNs(tp),
		name:      tp.TpName(),
	}
}

// NewManager creates a new manager
//
//revive:disable:unexported-return
func NewManager(cnf ManagerConf, sensorMgr SensorManager) (*manager, error) {
	mgr := &manager{
		cnf:       cnf,
		sensorMgr: sensorMgr,
		polNextID: 1,
	}
	return mgr, nil
}

func (m *manager) refresh(ctx context.Context) {
	refrAtt := m.attLog.NewAttempt("refresh")
	var err error
	var obj *Obj
	var data []byte
	defer func() {
		refrAtt.Complete(err)
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

	var loadedPolicies, unloadPolicies []policy
	var unloadMandateID string

	loadedPolicies, err = m.fetchAndLoadPolicies(ctx, refrAtt, obj)

	if err == nil {
		// success, unload existing policies (of old mandate)
		if m.obj != nil {
			unloadPolicies = m.loadedPolicies
			unloadMandateID = m.obj.id()
		}
		// and replace object and loaded policy lists
		m.obj = obj
		m.loadedPolicies = loadedPolicies
		m.obj.loadedTime = time.Now()
	} else {
		// failure, unload new policies
		unloadPolicies = loadedPolicies
		unloadMandateID = obj.id()
	}

	for _, pol := range unloadPolicies {
		attempt.RunAttempt(
			refrAtt.NewAttempt("unload policy").WithInfo("policy", pol.name).WithInfo("mandate", unloadMandateID),
			func() error {
				err := m.sensorMgr.DeleteTracingPolicy(ctx, pol.name, pol.namespace)
				if err != nil {
					logger.GetLogger().WithField("policy", pol.name).Warn("failed to unload mandate policy")
				}
				return err
			})
	}

}

// fetchAndLoadPolicies fetches and loads the policies in obj
// It returns an error if something went wrong, and the list of policies that were loaded
// Note that the list of loaded policies might be non-empty in case of an error.
func (m *manager) fetchAndLoadPolicies(ctx context.Context, refrAtt *attempt.InprAttempt, obj *Obj) ([]policy, error) {
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

	// second pass, attempt to load them
	loadedPolicies := make([]policy, 0, len(obj.Mandate.Policies))
	for i := range obj.Mandate.Policies {
		pol := &obj.Mandate.Policies[i]
		data := policyData[i]

		loadAtt := refrAtt.NewAttempt("load policy")
		mp, err := m.attemptLoadMandatePolicy(ctx, loadAtt, data, pol.mode_)
		if err != nil {
			return loadedPolicies, fmt.Errorf("failed to load policy %q: %w", pol.url_, err)
		}

		loadedPolicies = append(loadedPolicies, newPolicy(mp))
	}

	return loadedPolicies, nil
}

// attemptLoadMandatePolicy attempts to load a mandate policy
func (m *manager) attemptLoadMandatePolicy(
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

	ret, err = tracingpolicy.FromYAML(string(data))
	if err != nil {
		return nil, err
	}
	att.SetInfo("name", ret.TpName())

	// wrap the policy so that it can have a unique name based on the object id
	ret = m.NewMandatePolicy(ret)
	err = m.sensorMgr.AddTracingPolicy(ctx, ret)
	if err != nil {
		return nil, err
	}
	return ret, nil
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
		case stopCmdID:
			return
		}
	}
}

func (m *manager) status() *Status {
	var ret Status
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
