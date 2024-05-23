// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package crd

import (
	"context"
	"fmt"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/sensors"
	k8sconf "github.com/cilium/tetragon/pkg/watcher/conf"
	"github.com/isovalent/hubble-fgs/pkg/k8s/client/clientset/versioned"
	"github.com/isovalent/hubble-fgs/pkg/k8s/client/informers/externalversions"
	"github.com/isovalent/hubble-fgs/pkg/sandboxpolicy"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
)

func addSandboxPolicy(ctx context.Context, log logrus.FieldLogger, s *sensors.Manager, obj interface{}) {
	err := sandboxpolicy.AddSandboxPolicy(ctx, log, s, obj)
	if err != nil {
		log.WithError(err).Warn("failed to add sandbox policy")
	}
}

func deleteSandboxPolicy(ctx context.Context, log logrus.FieldLogger, s *sensors.Manager, obj interface{}) {
	var err error
	switch sp := obj.(type) {
	case *v1alpha1.SandboxPolicy:
		tpName := sandboxpolicy.TracingPolicyName(sp.ObjectMeta.Name)
		log.WithFields(logrus.Fields{
			"sp-name": sp.ObjectMeta.Name,
			"tp-name": tpName,
		}).Info("deleting sandbox policy")
		err = s.DeleteTracingPolicy(ctx, tpName, "")

	case *v1alpha1.SandboxPolicyNamespaced:
		tpName := sandboxpolicy.TracingPolicyName(sp.ObjectMeta.Name)
		log.WithFields(logrus.Fields{
			"sp-name":   sp.ObjectMeta.Name,
			"tp-name":   tpName,
			"namespace": sp.ObjectMeta.Namespace,
		}).Info("deleting sandbox policy")
		err = s.DeleteTracingPolicy(ctx, tpName, sp.ObjectMeta.Namespace)

	default:
		log.WithFields(logrus.Fields{
			"obj":      obj,
			"obj-type": fmt.Sprintf("%T", obj),
		}).Warn("deleteSandboxPolicy: invalid type")
		return
	}

	if err != nil {
		log.WithError(err).Warn("failed to delete sandbox policy")
	}
}

func WatchSandboxPolicy(ctx context.Context, s *sensors.Manager) {
	log := logger.GetLogger()
	log.Info("Starting to watch for sandbox policies")
	conf, err := k8sconf.K8sConfig()
	if err != nil {
		log.WithError(err).Fatal("couldn't get cluster config")
	}
	log = log.WithField("crd-watcher", true)
	client := versioned.NewForConfigOrDie(conf)
	factory := externalversions.NewSharedInformerFactory(client, 0)

	factory.Cilium().V1alpha1().SandboxPolicies().Informer().AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				addSandboxPolicy(ctx, log, s, obj)
			},
			DeleteFunc: func(obj interface{}) {
				deleteSandboxPolicy(ctx, log, s, obj)
			},
			UpdateFunc: func(oldObj interface{}, newObj interface{}) {
				deleteSandboxPolicy(ctx, log, s, oldObj)
				addSandboxPolicy(ctx, log, s, newObj)
			}})

	factory.Cilium().V1alpha1().SandboxPoliciesNamespaced().Informer().AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				addSandboxPolicy(ctx, log, s, obj)
			},
			DeleteFunc: func(obj interface{}) {
				deleteSandboxPolicy(ctx, log, s, obj)
			},
			UpdateFunc: func(oldObj interface{}, newObj interface{}) {
				deleteSandboxPolicy(ctx, log, s, oldObj)
				addSandboxPolicy(ctx, log, s, newObj)
			}})

	go factory.Start(wait.NeverStop)
	factory.WaitForCacheSync(wait.NeverStop)
	log.Info("Started watching sandbox policies")
}
