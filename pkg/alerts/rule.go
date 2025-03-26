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
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/google/cel-go/cel"

	"github.com/cilium/tetragon/pkg/fileutils"
	"github.com/cilium/tetragon/pkg/filters"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"

	eeOption "github.com/isovalent/hubble-fgs/pkg/option"
)

var (
	cef = filters.NewCELExpressionFilter(logger.GetLogger())
)

type rule struct {
	cel      cel.Program
	name     string
	message  string
	tags     []string
	severity string

	jsonEncoder *jsonEncoder
}

type RuleManager interface {
	AddAlertRule(ar *v1alpha1.AlertRule) error
	DeleteAlertRule(name string)
}

type ruleManager struct {
	rules map[string]*rule
	mutex sync.RWMutex
}

func NewRuleManager() RuleManager {
	return newRuleManager()
}

func newRuleManager() *ruleManager {
	return &ruleManager{
		rules: make(map[string]*rule),
	}
}

func (r *ruleManager) AddAlertRule(ar *v1alpha1.AlertRule) error {
	if ar == nil {
		return nil
	}

	celProgram, err := cef.CompileCEL(ar.Spec.Expression)
	if err != nil {
		return err
	}
	name := ar.GetName()
	var encoder *jsonEncoder
	r.mutex.Lock()
	if rule, ok := r.rules[name]; ok {
		// we have the same rule, we can re-use the jsonEncoder to guarantee
		// that JSON records are written atomically to the file.
		encoder = rule.jsonEncoder
	}
	r.mutex.Unlock()

	// otherwise, let's open a new file
	if eeOption.Config.AlertsExportDir != "" && encoder == nil {
		perms, _ := fileutils.RegularFilePerms(option.Config.ExportFilePerm)
		filename := filepath.Join(eeOption.Config.AlertsExportDir, name+".log")
		fh, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, perms)
		if err != nil {
			return fmt.Errorf("failed to open a file: %w", err)
		}
		encoder = newJsonEncoder(fh)
	}

	// now we can replace the rule
	r.mutex.Lock()
	r.rules[name] = &rule{
		cel:         celProgram,
		name:        name,
		message:     ar.Spec.Message,
		tags:        ar.Spec.Tags,
		severity:    ar.Spec.Severity,
		jsonEncoder: encoder,
	}
	r.mutex.Unlock()
	return nil
}

func (r *ruleManager) DeleteAlertRule(name string) {
	r.mutex.Lock()
	if rule, ok := r.rules[name]; ok {
		if rule.jsonEncoder != nil {
			rule.jsonEncoder.Close()
		}
		delete(r.rules, name)
	}
	r.mutex.Unlock()
}
