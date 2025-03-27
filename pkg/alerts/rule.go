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
	cel         cel.Program
	name        string
	message     string
	tags        []string
	severity    string
	jsonEncoder *jsonEncoder
}

type RuleManager interface {
	AddAlertRule(ar *v1alpha1.AlertRule) error
	DeleteAlertRule(name string)

	// Add an alert rule that writes on a specific filename.
	//
	// NB(kkourt): The mandate code uses this functio so that it can install two alert rules
	// with the same name. In the future, we might expose the ability to specify a filename in
	// the alert rule in the spec as well.
	//
	// WARNING: If the fname argument is ever provided by the user, we need to validate it
	// (e.g., using ValidateDNS1123Subdomain) before calling this function.
	AddAlertRuleWithFilename(ar *v1alpha1.AlertRule, fname string) error
}

type ruleManager struct {
	rules    map[string]*rule
	encoders map[string]*jsonEncoder
	mutex    sync.RWMutex
}

func NewRuleManager() RuleManager {
	return newRuleManager()
}

func newRuleManager() *ruleManager {
	return &ruleManager{
		rules:    make(map[string]*rule),
		encoders: make(map[string]*jsonEncoder),
	}
}

// Add an alert rule that writes on a specific filename.
// This is useful for the mandate code. If you want to call this function, ensure that fname is
// sanitized if it comes from the user (e.g., using ValidateDNS1123Subdomain)
func (r *ruleManager) AddAlertRuleWithFilename(ar *v1alpha1.AlertRule, fname string) error {
	if ar == nil {
		return nil
	}

	celProgram, err := cef.CompileCEL(ar.Spec.Expression)
	if err != nil {
		return err
	}

	var encoder *jsonEncoder
	var newEncoder bool
	// use an existing encoder if one exists
	r.mutex.Lock()
	encoder, _ = r.encoders[fname]
	if encoder != nil {
		encoder.IncRef()
	}
	r.mutex.Unlock()

	// if no existing encoder exists, let's create a new one by openning a new file
	if eeOption.Config.AlertsExportDir != "" && encoder == nil {
		perms, _ := fileutils.RegularFilePerms(option.Config.ExportFilePerm)
		filename := filepath.Join(eeOption.Config.AlertsExportDir, fname)
		fh, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, perms)
		if err != nil {
			return fmt.Errorf("failed to open a file: %w", err)
		}
		encoder = newJsonEncoder(fh, fname)
		newEncoder = true
	}

	name := ar.GetName()
	r.mutex.Lock()
	// if we are replacing a rule, decref its encoder
	if oldRule, ok := r.rules[name]; ok {
		r.encoderDecref(oldRule)
	}
	r.rules[name] = &rule{
		cel:         celProgram,
		name:        ar.GetName(),
		message:     ar.Spec.Message,
		tags:        ar.Spec.Tags,
		severity:    ar.Spec.Severity,
		jsonEncoder: encoder,
	}
	if newEncoder {
		r.encoders[fname] = encoder
	}
	r.mutex.Unlock()
	return nil
}

func (r *ruleManager) AddAlertRule(ar *v1alpha1.AlertRule) error {
	if ar == nil {
		return nil
	}
	return r.AddAlertRuleWithFilename(ar, ar.GetName()+".log")
}

func (r *ruleManager) DeleteAlertRule(name string) {
	r.mutex.Lock()
	if rule, ok := r.rules[name]; ok {
		r.encoderDecref(rule)
		delete(r.rules, name)
	}
	r.mutex.Unlock()
}

// encoderDecref decreases the reference counter of rules jsonEncoder, and removes it from
// r.encoders if the reference count is 0
func (r *ruleManager) encoderDecref(rule *rule) {
	je := rule.jsonEncoder
	if je == nil {
		return
	}
	cnt := je.DecRef()
	if cnt == int32(0) {
		delete(r.encoders, je.fname)
	}
}
