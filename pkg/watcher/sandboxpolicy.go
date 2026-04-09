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
	"github.com/cilium/tetragon/pkg/sensors"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"

	"github.com/isovalent/hubble-fgs/pkg/sandboxpolicy"
)

func addSandboxPolicy(ctx context.Context, log logger.FieldLogger, s *sensors.Manager, obj interface{}) {
	err := sandboxpolicy.AddSandboxPolicy(ctx, log, s, obj)
	if err != nil {
		log.Warn("failed to add sandbox policy", logfields.Error, err)
	}
}

func deleteSandboxPolicy(ctx context.Context, log logger.FieldLogger, s *sensors.Manager, obj interface{}) {
	var err error
	switch sp := obj.(type) {
	case *v1alpha1.SandboxPolicy:
		tpName := sandboxpolicy.TracingPolicyName(sp.Name)
		log.Info("deleting sandbox policy", "sp-name", sp.Name, "tp-name", tpName)
		err = s.DeleteTracingPolicy(ctx, tpName, "")

	case *v1alpha1.SandboxPolicyNamespaced:
		tpName := sandboxpolicy.TracingPolicyName(sp.Name)
		log.Info("deleting sandbox policy", "sp-name", sp.Name, "tp-name", tpName, "namespace", sp.Namespace)
		err = s.DeleteTracingPolicy(ctx, tpName, sp.Namespace)

	default:
		log.Warn("deleteSandboxPolicy: invalid type", "obj", obj, "obj-type", fmt.Sprintf("%T", obj))
		return
	}

	if err != nil {
		log.Warn("failed to delete sandbox policy", logfields.Error, err)
	}
}

func sandboxPolicyNeedsUpdate(
	oldObj interface{}, newObj interface{},
) (bool, error) {
	switch oldSp := oldObj.(type) {
	case *v1alpha1.SandboxPolicy:
		newSp, ok := newObj.(*v1alpha1.SandboxPolicy)
		if !ok {
			return false, fmt.Errorf("sandboxpolicy update type mismatch: old:%T new:%T", oldSp, newSp)
		}
		return oldSp.ResourceVersion != newSp.ResourceVersion, nil
	case *v1alpha1.SandboxPolicyNamespaced:
		newSp, ok := newObj.(*v1alpha1.SandboxPolicyNamespaced)
		if !ok {
			return false, fmt.Errorf("sandboxpolicy update type mismatch: old:%T new:%T", oldSp, newSp)
		}
		return oldSp.ResourceVersion != newSp.ResourceVersion, nil
	default:
		return false, fmt.Errorf("sandboxpolicy update unexpected types: old:%T new:%T", oldObj, newObj)
	}
}

func updateSandboxPolicy(
	ctx context.Context, log logger.FieldLogger,
	s *sensors.Manager, oldObj interface{}, newObj interface{},
) {
	upd, err := sandboxPolicyNeedsUpdate(oldObj, newObj)
	if err != nil {
		log.Warn("error in updating sandbox policy: %s", err)
		return
	}

	if upd {
		log := log.With("watcher-event", "update")
		deleteSandboxPolicy(ctx, log, s, oldObj)
		addSandboxPolicy(ctx, log, s, newObj)
	}
}

func AddSandboxPolicyInformer(ctx context.Context, m *manager.ControllerManager, s *sensors.Manager) error {
	log := logger.GetLogger().With("crd-watcher", true)
	spInformer, err := m.Manager.GetCache().GetInformer(ctx, &v1alpha1.SandboxPolicy{})
	if err != nil {
		return err
	}
	_, err = spInformer.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				addSandboxPolicy(ctx, log, s, obj)
			},
			DeleteFunc: func(obj interface{}) {
				deleteSandboxPolicy(ctx, log, s, obj)
			},
			UpdateFunc: func(oldObj interface{}, newObj interface{}) {
				updateSandboxPolicy(ctx, log, s, oldObj, newObj)
			}})
	if err != nil {
		return err
	}

	spnInformer, err := m.Manager.GetCache().GetInformer(ctx, &v1alpha1.SandboxPolicyNamespaced{})
	if err != nil {
		return err
	}
	_, err = spnInformer.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				addSandboxPolicy(ctx, log, s, obj)
			},
			DeleteFunc: func(obj interface{}) {
				deleteSandboxPolicy(ctx, log, s, obj)
			},
			UpdateFunc: func(oldObj interface{}, newObj interface{}) {
				updateSandboxPolicy(ctx, log, s, oldObj, newObj)
			}})
	return err
}
