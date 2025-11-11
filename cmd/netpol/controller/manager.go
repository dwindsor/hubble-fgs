package controller

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/go-logr/logr"
	"github.com/isovalent/ipa/k8s/apis/isovalent.com/v1alpha1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
	ctrl "sigs.k8s.io/controller-runtime"
	controllerruntimelog "sigs.k8s.io/controller-runtime/pkg/log"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

var v1alpha1Scheme = func() *runtime.Scheme {
	scheme := runtime.NewScheme()
	v1alpha1.AddToScheme(scheme)
	apiextensionsv1.AddToScheme(scheme)
	return scheme
}()

func newManager(log *slog.Logger, cfg Config, jg job.Group) (ctrl.Manager, error) {
	if cfg.KubeConfigPath != "" {
		// Pass it onto GetConfig()
		os.Setenv("KUBECONFIG", cfg.KubeConfigPath)
	}
	restConfig, err := ctrl.GetConfig()
	if err != nil {
		return nil, err
	}
	logr := logr.FromSlogHandler(log.Handler())
	controllerruntimelog.SetLogger(logr)
	mngr, err := ctrl.NewManager(
		restConfig,
		ctrl.Options{
			Scheme:  v1alpha1Scheme,
			Logger:  logr,
			Metrics: metricsserver.Options{BindAddress: "0"},
		},
	)
	if err != nil {
		return nil, err
	}

	jg.Add(
		job.OneShot("run-manager", func(ctx context.Context, health cell.Health) error {
			return mngr.Start(ctx)
		}, job.WithShutdown()))

	return mngr, err
}

func waitForCRDs(ctx context.Context, log *slog.Logger, mngr ctrl.Manager, crds ...string) error {
	if len(crds) == 0 {
		return nil
	}
	var mu sync.Mutex
	remaining := sets.New(crds...)
	informer, err := mngr.GetCache().GetInformer(ctx, &apiextensionsv1.CustomResourceDefinition{})
	if err != nil {
		return err
	}
	done := make(chan struct{})
	_, err = informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			crdObject, ok := obj.(*apiextensionsv1.CustomResourceDefinition)
			mu.Lock()
			defer mu.Unlock()
			if ok && remaining.Has(crdObject.Name) {
				remaining.Delete(crdObject.Name)
				if len(remaining) == 0 {
					close(done)
				}
			}
		},
	})
	if err != nil {
		return err
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
	case <-ticker.C:
		mu.Lock()
		log.Info("Still waiting for CRDs", "remaining", crds)
		mu.Unlock()
	}

	// Asynchronously ask the informer to go away.
	mngr.GetCache().RemoveInformer(ctx, &apiextensionsv1.CustomResourceDefinition{})

	return nil
}
