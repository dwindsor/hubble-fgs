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
	"fmt"

	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

type TestSensorManager struct {
	pols map[string]struct{}
}

func NewTestSensorManager() *TestSensorManager {
	return &TestSensorManager{
		pols: make(map[string]struct{}),
	}
}

func (tsm *TestSensorManager) AddTracingPolicy(_ context.Context, tp tracingpolicy.TracingPolicy) error {
	name := tp.TpName()
	if _, exists := tsm.pols[name]; exists {
		return fmt.Errorf("policy named %q already exists", name)
	}
	tsm.pols[name] = struct{}{}
	return nil
}

func (tsm *TestSensorManager) DeleteTracingPolicy(_ context.Context, name, _ string) error {
	if _, exists := tsm.pols[name]; !exists {
		return fmt.Errorf("policy named %q does not exists", name)
	}
	delete(tsm.pols, name)
	return nil
}
