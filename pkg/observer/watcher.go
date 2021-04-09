package observer

import (
	"context"
	"time"

	"github.com/covalentio/hubble-fgs/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/covalentio/hubble-fgs/pkg/k8s/client/clientset/versioned"
	"github.com/covalentio/hubble-fgs/pkg/k8s/client/informers/externalversions"
	"github.com/covalentio/hubble-fgs/pkg/logger"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

func (k *ObserverKprobe) watchTracePolicy(ctx context.Context) {
	log := logger.GetLogger()
	conf, err := rest.InClusterConfig()
	if err != nil {
		logger.GetLogger().WithError(err).Fatal("couldn't get cluster config")
	}
	client := versioned.NewForConfigOrDie(conf)
	factory := externalversions.NewSharedInformerFactory(client, 5*time.Minute)
	informer := factory.Isovalent().V1alpha1().TracingPolicies()
	informer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			policy, ok := obj.(*v1alpha1.TracingPolicy)
			if !ok {
				log.WithField("obj", obj).Warn("invalid type in add func")
				return
			}
			log.WithField("policy", policy.Spec).Info("tracing policy added")
			err := k.AddTracingPolicy(ctx, policy.ObjectMeta.Name, &policy.Spec)
			if err != nil {
				log.WithError(err).Warn("adding tracing policy failed")
			}
		},
		UpdateFunc: func(oldObj interface{}, newObj interface{}) {
			oldPolicy, ok := oldObj.(*v1alpha1.TracingPolicy)
			if !ok {
				logger.GetLogger().WithField("oldObj", oldObj).Warn("invalid oldObj type in update func")
				return
			}
			newPolicy, ok := newObj.(*v1alpha1.TracingPolicy)
			if !ok {
				logger.GetLogger().WithField("newObj", newObj).Warn("invalid newObj type in update func")
				return
			}
			/* Deep Equals */
			if oldPolicy.ResourceVersion == newPolicy.ResourceVersion {
				return
			}
			logger.GetLogger().WithFields(logrus.Fields{
				"oldPolicy": oldPolicy.Spec,
				"newPolicy": newPolicy.Spec,
			}).Info("tracing policy updated")
			err := k.RemoveSensor(ctx, oldPolicy.ObjectMeta.Name)
			if err != nil {
				log.WithError(err).Warnf("Failed to remove sensor %s to perform update", oldPolicy.ObjectMeta.Name)
				return
			}
			err = k.AddTracingPolicy(ctx, newPolicy.ObjectMeta.Name, &newPolicy.Spec)
			if err != nil {
				log.WithError(err).Warn("adding new tracing policy failed")
			}

		},
		DeleteFunc: func(obj interface{}) {
			policy, ok := obj.(*v1alpha1.TracingPolicy)
			if !ok {
				logger.GetLogger().WithField("obj", obj).Warn("invalid type in delete func")
				return
			}
			logger.GetLogger().WithField("policy", policy.Spec).Info("tracing policy deleted")
			err := k.RemoveSensor(ctx, policy.ObjectMeta.Name)
			if err != nil {
				log.WithError(err).Warnf("Failed to remove sensor %s to perform update", policy.ObjectMeta.Name)
				return
			}

		},
	})
	go factory.Start(wait.NeverStop)
	factory.WaitForCacheSync(wait.NeverStop)
	logger.GetLogger().Info("Started watching tracing policies")
	select {}
}
