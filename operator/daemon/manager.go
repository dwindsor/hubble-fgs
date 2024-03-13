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
	ctrlcache "sigs.k8s.io/controller-runtime/pkg/cache"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/k8s/version"

	"github.com/isovalent/hubble-fgs/operator/options"
)

var (
	// TODO (FGI): avoid a package variable for the logger.
	log    = logging.DefaultLogger.WithField(logfields.LogSubsys, "tetragon-operator")
	scheme = runtime.NewScheme()
)

func Manage() error {
	log.Info("instantiation of the manager of the Tetragon agent")
	client, err := getK8SClient()
	if err != nil {
		return err
	}

	ctx := context.Background()

	log.Info("checking if the operator ConfigMap already exists")
	_, err = client.CoreV1().ConfigMaps(options.Config.DaemonSetNamespace).Get(ctx, OperatorConfigMapName, metav1.GetOptions{})
	if err != nil {
		if !errors.IsNotFound(err) {
			return fmt.Errorf("failed to get Tetragon operator ConfigMap: %w", err)
		}
		// Creating an empty ConfigMap ensures that the reconciliation is triggered.
		// Default settings for the agent DaemonSet and ConfigMap are applied.
		log.Info("Tetragon operator ConfigMap does not exist, creating an empty one (default configuration)")
		_, err = client.CoreV1().ConfigMaps(options.Config.DaemonSetNamespace).Create(
			ctx, defaultOperatorConfigMap(options.Config.DaemonSetNamespace, OperatorConfigMapName), metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("failed to create Tetragon daemon set: %w", err)
		}
		// The new ConfigMap does not need to get mounted as its content is retrieved through the API,
		// which provides a nicer interface for the reconciliation.
	}

	log.Info("starting Tetragon daemon set manager")
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{Scheme: scheme,
		// Only watching the operator namespace
		Cache: ctrlcache.Options{DefaultNamespaces: map[string]ctrlcache.Config{options.Config.DaemonSetNamespace: {}}}})
	if err != nil {
		return fmt.Errorf("failed to create Tetragon daemon set reconciler manager: %w", err)
	}

	reconciler := &Reconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		Log:    ctrl.Log.WithName("tetragon-ds-reconciler"),
	}
	if err := reconciler.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("failed to create Tetragon daemon set reconciler: %w", err)
	}

	go func() {
		if err := mgr.Start(ctx); err != nil {
			log.Fatalf("reconciler Tetragon daemon set manager failed: %s", err)
		}
		//TODO (FGI): handle graceful termination through context
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
