// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package watcher

import (
	"fmt"

	"github.com/sirupsen/logrus"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/watcher"
	"github.com/isovalent/hubble-fgs/pkg/alerts"
)

func addAlertRule(obj any) {
	ar := convertToAlertRule(obj)

	if ar == nil {
		logger.GetLogger().Info("Can't add alert rule: it's nil.")
		return
	}

	err := alerts.AddAlertRule(ar)

	if err != nil {
		logger.GetLogger().WithError(err).WithFields(logrus.Fields{
			"name": ar.GetName(),
		}).Warn("Failed to add alert rule")
	} else {
		logger.GetLogger().WithFields(logrus.Fields{
			"name": ar.GetName(),
		}).Info("Added alert rule")
	}
}

func updateAlertRule(oldObj any, newObj any) {
	oldAr := convertToAlertRule(oldObj)
	newAr := convertToAlertRule(newObj)

	if oldAr == nil || newAr == nil {
		logger.GetLogger().Info("Can't update an alert rule: it's nil.")
		return
	}
	if oldAr.GetName() != newAr.GetName() {
		logger.GetLogger().WithFields(logrus.Fields{
			"old-name": oldAr.GetName(),
			"new-name": newAr.GetName(),
		}).Warn("Can't update alert rule: old and new names are different.")
		return
	}

	// Alert rules are indexed by name, so adding the new alert rule will
	// overwrite the old one.
	err := alerts.AddAlertRule(newAr)

	if err != nil {
		logger.GetLogger().WithError(err).WithFields(logrus.Fields{
			"name": newAr.GetName(),
		}).Warn("Failed to update alert rule")
	} else {
		logger.GetLogger().WithFields(logrus.Fields{
			"name": newAr.GetName(),
		}).Info("Updated alert rule")
	}
}

func deleteAlertRule(obj any) {
	ar := convertToAlertRule(obj)

	if ar == nil {
		logger.GetLogger().Info("Can't delete alert rule: it's nil.")
		return
	}

	alerts.DeleteAlertRule(ar.GetName())

	logger.GetLogger().WithFields(logrus.Fields{
		"name": ar.GetName(),
	}).Info("Deleted alert rule")
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
		logger.GetLogger().WithFields(logrus.Fields{
			"obj":      obj,
			"obj-type": fmt.Sprintf("%T", obj),
		}).Warn("Received invalid type, expected *v1alpha1.AlertRule")
	}
	return nil
}

func AddAlertRuleInformer(w watcher.Watcher) error {
	if w == nil {
		return fmt.Errorf("k8s watcher not initialized")
	}
	factory := w.GetCRDInformerFactory()
	if factory == nil {
		return fmt.Errorf("CRD informer factory not initialized")
	}

	informer := factory.Cilium().V1alpha1().AlertRules().Informer()
	informer.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj any) {
				addAlertRule(obj)
			},
			UpdateFunc: func(oldObj any, newObj any) {
				updateAlertRule(oldObj, newObj)
			},
			DeleteFunc: func(obj any) {
				deleteAlertRule(obj)
			}})
	err := w.AddInformer("AlertRule", informer, nil)
	if err != nil {
		return fmt.Errorf("failed to add AlertRule informer: %w", err)
	}

	return nil
}
