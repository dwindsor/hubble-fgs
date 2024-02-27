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
	var err error
	switch sp := obj.(type) {
	case *v1alpha1.SandboxPolicy:
		var tp *sandboxpolicy.SandboxTracingPolicy
		tp, err = sandboxpolicy.ToTracingPolicy(sp)
		if err != nil {
			log.WithFields(logrus.Fields{
				"sandbox-policy-name": sp.ObjectMeta.Name,
			}).WithError(err).Warn("addSandboxPolicy: failed to convert to tracing policy")
			return
		}
		log.WithFields(logrus.Fields{
			"sp-name": sp.ObjectMeta.Name,
			"tp-name": tp.TpName(),
			"tp-info": tp.TpInfo(),
		}).Info("adding sandbox policy")
		err = s.AddTracingPolicy(ctx, tp)

	default:
		log.WithFields(logrus.Fields{
			"obj":      obj,
			"obj-type": fmt.Sprintf("%T", obj),
		}).Warn("addSandboxPolicy: invalid type")
		return
	}

	if err != nil {
		log.WithError(err).Warn("failed to add sandbox policy")
	}
}

func WatchSandboxPolicy(ctx context.Context, s *sensors.Manager) {
	log := logger.GetLogger()
	log.Info("Starting to watch for sandbox policies")
	conf, err := k8sconf.K8sConfig()
	if err != nil {
		log.WithError(err).Fatal("couldn't get cluster config")
	}
	client := versioned.NewForConfigOrDie(conf)
	factory := externalversions.NewSharedInformerFactory(client, 0)

	factory.Cilium().V1alpha1().SandboxPolicies().Informer().AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				addSandboxPolicy(ctx, log, s, obj)
			},
			DeleteFunc: func(_ interface{}) {
				// TODO
			},
			UpdateFunc: func(_ interface{}, _ interface{}) {
				// TODO
			}})

	go factory.Start(wait.NeverStop)
	factory.WaitForCacheSync(wait.NeverStop)
	log.Info("Started watching sandbox policies")
}
