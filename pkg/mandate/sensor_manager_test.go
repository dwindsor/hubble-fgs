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
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/cilium/tetragon/pkg/policyconf"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

type conf struct {
	mode policyconf.Mode
}

type TestSensorManager struct {
	pols map[string]conf
	mu   sync.Mutex
}

func NewTestSensorManager() *TestSensorManager {
	return &TestSensorManager{
		pols: make(map[string]conf),
	}
}

func getSpecMode(opts []v1alpha1.OptionSpec) policyconf.Mode {
	keyPolicyMode := "policy-mode"
	for _, opt := range opts {
		if opt.Name == keyPolicyMode {
			mode, err := policyconf.ParseMode(opt.Value)
			if err != nil {
				// function used only for testing, so it's OK to panic
				panic(fmt.Sprintf("invalid policy mode: %s", opt.Value))
			}
			return mode
		}
	}
	return policyconf.EnforceMode
}

func (tsm *TestSensorManager) policyMode(t *testing.T, polName string) policyconf.Mode {
	tsm.mu.Lock()
	defer tsm.mu.Unlock()

	for name, conf := range tsm.pols {
		if polName == name {
			return conf.mode
		}
	}
	require.True(t, false, fmt.Sprintf("policy %q not found", polName))
	return policyconf.InvalidMode
}

func (tsm *TestSensorManager) AddTracingPolicy(_ context.Context, tp tracingpolicy.TracingPolicy) error {
	tsm.mu.Lock()
	defer tsm.mu.Unlock()

	name := tp.TpName()
	mode := getSpecMode(tp.TpSpec().Options)
	if _, exists := tsm.pols[name]; exists {
		return fmt.Errorf("policy named %q already exists", name)
	}
	tsm.pols[name] = conf{mode}
	return nil
}

func (tsm *TestSensorManager) DeleteTracingPolicy(_ context.Context, name, _, _ string) error {
	tsm.mu.Lock()
	defer tsm.mu.Unlock()

	if _, exists := tsm.pols[name]; !exists {
		return fmt.Errorf("policy named %q does not exists", name)
	}
	delete(tsm.pols, name)
	return nil
}

func (tsm *TestSensorManager) ConfigureTracingPolicy(_ context.Context, conf *tetragon.ConfigureTracingPolicyRequest) error {
	tsm.mu.Lock()
	defer tsm.mu.Unlock()

	name := conf.GetName()
	val, exists := tsm.pols[name]
	if !exists {
		return fmt.Errorf("policy named %q does not exists", name)
	}

	if conf.Mode != nil {
		switch *conf.Mode {
		case tetragon.TracingPolicyMode_TP_MODE_ENFORCE:
			val.mode = policyconf.EnforceMode
		case tetragon.TracingPolicyMode_TP_MODE_MONITOR:
			val.mode = policyconf.MonitorMode
		default:
			val.mode = policyconf.InvalidMode
		}
	}
	tsm.pols[name] = val
	return nil
}
