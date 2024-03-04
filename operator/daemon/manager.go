package daemon

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/k8s/version"

	"github.com/isovalent/hubble-fgs/operator/options"
)

var (
	log    = logging.DefaultLogger.WithField(logfields.LogSubsys, "tetragon-operator")
	scheme = runtime.NewScheme()
)

func Manage() error {
	client, err := getK8SClient()
	if err != nil {
		return err
	}

	ctx := context.Background()

	log.Info("checking if Tetragon daemon set already exists")
	ds, err := client.AppsV1().DaemonSets(options.Config.DaemonSetNamespace).Get(ctx, dsName, metav1.GetOptions{})
	if err != nil {
		if !errors.IsNotFound(err) {
			return fmt.Errorf("failed to get Tetragon daemon set: %w", err)
		}
		log.Info("Tetragon daemon set does not exist, creating")
		ds, err = client.AppsV1().DaemonSets(options.Config.DaemonSetNamespace).Create(ctx, daemonSet(), metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("failed to create Tetragon daemon set: %w", err)
		}
		log.Info("Tetragon daemon set created")
	}

	if ds.Labels[dsManagedByLabel] != dsManagedByValue {
		log.Info("Tetragon daemon set exists and is not manager by operator")
		return nil
	}

	log.Info("starting Tetragon daemon set manager")
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{Scheme: scheme})
	if err != nil {
		return fmt.Errorf("failed to create Tetragon daemon set reconciler manager: %w", err)
	}

	reconciler := &Reconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("tetragon-ds-reconciler"),
	}
	if err := reconciler.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("failed to create Tetragon daemon set reconciler: %w", err)
	}

	go func() {
		if err := mgr.Start(ctx); err != nil {
			log.Fatalf("reconciler Tetragon daemon set manager failed: %s", err)
		}
		//TODO: handle graceful termination through context
	}()
	return nil
}

func getK8SClient() (*kubernetes.Clientset, error) {
	restConfig, err := getConfig()
	if err != nil {
		return nil, fmt.Errorf("unable to check k8s configuration: %w", err)
	}

	client, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to create k8s client: %w", err)
	}

	if err := version.UpdateK8sServerVersion(client); err != nil {
		return nil, fmt.Errorf("unable to check k8s version: %w", err)
	}
	return client, nil
}

func getConfig() (*rest.Config, error) {
	if options.Config.KubeCfgPath != "" {
		return clientcmd.BuildConfigFromFlags("", options.Config.KubeCfgPath)
	}
	return rest.InClusterConfig()
}

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(v1alpha1.AddToScheme(scheme))
}
