// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build !nok8s

package watcher

import (
	"context"
	"fmt"

	"github.com/cilium/tetragon/pkg/logger/logfields"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/manager"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"

	"github.com/isovalent/hubble-fgs/pkg/alerts"
)

func addAlertRule(obj any, rm alerts.RuleManager) {
	ar := convertToAlertRule(obj)

	if ar == nil {
		logger.GetLogger().Info("Can't add alert rule: it's nil.")
		return
	}

	err := rm.AddAlertRule(ar)

	if err != nil {
		logger.GetLogger().Warn("Failed to add alert rule", "name", ar.GetName(), logfields.Error, err)
	} else {
		logger.GetLogger().Info("Added alert rule", "name", ar.GetName())
	}
}

func updateAlertRule(oldObj any, newObj any, rm alerts.RuleManager) {
	oldAr := convertToAlertRule(oldObj)
	newAr := convertToAlertRule(newObj)

	if oldAr == nil || newAr == nil {
		logger.GetLogger().Info("Can't update an alert rule: it's nil.")
		return
	}
	// We might get a bunch of update events from periodic re-syncs. If the
	// resource version hasn't changed, ignore the event.
	if oldAr.ResourceVersion == newAr.ResourceVersion {
		return
	}
	if oldAr.GetName() != newAr.GetName() {
		logger.GetLogger().Warn("Can't update alert rule: old and new names are different.",
			"old-name", oldAr.GetName(),
			"new-name", newAr.GetName())
		return
	}

	// Alert rules are indexed by name, so adding the new alert rule will
	// overwrite the old one.
	err := rm.AddAlertRule(newAr)

	if err != nil {
		logger.GetLogger().Warn("Failed to update alert rule", "name", newAr.GetName(), logfields.Error, err)
	} else {
		logger.GetLogger().Info("Updated alert rule", "name", newAr.GetName())
	}
}

func deleteAlertRule(obj any, rm alerts.RuleManager) {
	ar := convertToAlertRule(obj)

	if ar == nil {
		logger.GetLogger().Info("Can't delete alert rule: it's nil.")
		return
	}

	rm.DeleteAlertRule(ar.GetName())

	logger.GetLogger().Info("Deleted alert rule", "name", ar.GetName())
}

func convertToAlertRule(obj any) *v1alpha1.AlertRule {
	switch concreteObj := obj.(type) {
	case *v1alpha1.AlertRule:
		return concreteObj
	case cache.DeletedFinalStateUnknown:
		deletedObj, ok := concreteObj.Obj.(*v1alpha1.AlertRule)
		if ok {
			return deletedObj
		}
	default:
		logger.GetLogger().Warn("Received invalid type, expected *v1alpha1.AlertRule",
			"obj", obj, "obj-type", fmt.Sprintf("%T", obj))
	}
	return nil
}

func AddAlertRuleInformer(ctx context.Context, m *manager.ControllerManager, rm alerts.RuleManager) error {
	informer, err := m.Manager.GetCache().GetInformer(ctx, &v1alpha1.AlertRule{})
	if err != nil {
		return nil
	}
	_, err = informer.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj any) {
				addAlertRule(obj, rm)
			},
			UpdateFunc: func(oldObj any, newObj any) {
				updateAlertRule(oldObj, newObj, rm)
			},
			DeleteFunc: func(obj any) {
				deleteAlertRule(obj, rm)
			}})
	return err
}
