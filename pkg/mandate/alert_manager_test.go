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
	"fmt"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

type testAlert struct {
	fname string
}

type TestAlertManager struct {
	alerts map[string]testAlert
}

func NewTestAlertManager() *TestAlertManager {
	return &TestAlertManager{
		alerts: make(map[string]testAlert),
	}
}

// NB: note that the aactual Alert implementation does not return an error if the user tries to add
// an alert with a name that already exists. It's useful to have this behavior for testing.
func (am *TestAlertManager) AddAlertRuleWithFilename(ar *v1alpha1.AlertRule, fname string) error {
	name := ar.GetName()
	if _, exists := am.alerts[name]; exists {
		return fmt.Errorf("alert named %q already exists", name)
	}
	am.alerts[name] = testAlert{fname}
	return nil
}

func (am *TestAlertManager) DeleteAlertRule(name string) {
	delete(am.alerts, name)
}
