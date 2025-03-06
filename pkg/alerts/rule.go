//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package alerts

import (
	"sync"

	"github.com/google/cel-go/cel"

	"github.com/cilium/tetragon/pkg/filters"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
)

var (
	cef        = filters.NewCELExpressionFilter(logger.GetLogger())
	rules      = map[string]*rule{}
	rulesMutex sync.RWMutex
)

type rule struct {
	cel      cel.Program
	name     string
	message  string
	tags     []string
	severity string
}

func AddAlertRule(ar *v1alpha1.AlertRule) error {
	if ar == nil {
		return nil
	}

	celProgram, err := cef.CompileCEL(ar.Spec.Expression)
	if err != nil {
		return err
	}

	rulesMutex.Lock()
	rules[ar.GetName()] = &rule{
		cel:      celProgram,
		name:     ar.GetName(),
		message:  ar.Spec.Message,
		tags:     ar.Spec.Tags,
		severity: ar.Spec.Severity,
	}
	rulesMutex.Unlock()
	return nil
}

func DeleteAlertRule(name string) {
	delete(rules, name)
}
