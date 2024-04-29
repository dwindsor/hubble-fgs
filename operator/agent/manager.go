package agent

import (
	"context"
	"fmt"

	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
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

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/k8s/version"

	"github.com/isovalent/hubble-fgs/operator/options"
)

var (
	scheme = runtime.NewScheme()
)

func Manage(cfg options.OperatorConfig) error {
	log := ctrl.Log.WithName("tetragon-operator")
	log.Info("instantiation of the manager of the Tetragon agent")
	client, err := getK8SClient(cfg.KubeconfigPath)
	if err != nil {
		return err
	}

	ctx := context.Background()

	log.Info("checking if the operator ConfigMap already exists")
	opCM, err := client.CoreV1().ConfigMaps(cfg.TetragonNamespace).Get(ctx, OperatorConfigMapName, metav1.GetOptions{})
	if err != nil {
		if !errors.IsNotFound(err) {
			return fmt.Errorf("failed to get Tetragon operator ConfigMap: %w", err)
		}
		// Creating an empty ConfigMap ensures that the reconciliation is triggered.
		// Default settings for the agent DaemonSet and ConfigMap are applied.
		log.Info("Tetragon operator ConfigMap does not exist, creating an empty one (default configuration)")
		opCM, err = client.CoreV1().ConfigMaps(cfg.TetragonNamespace).Create(
			ctx, DefaultOperatorConfigMap(log, cfg.TetragonNamespace, OperatorConfigMapName), metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("failed to create Tetragon daemon set: %w", err)
		}
		// The new ConfigMap does not need to get mounted as its content is retrieved through the API,
		// which provides a nicer interface for the reconciliation.
	}

	log.Info("starting Tetragon daemon set manager")
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{Scheme: scheme,
		// Only watching the operator namespace
		Cache: ctrlcache.Options{DefaultNamespaces: map[string]ctrlcache.Config{cfg.TetragonNamespace: {}}}})
	if err != nil {
		return fmt.Errorf("failed to create Tetragon daemon set reconciler manager: %w", err)
	}

	reconciler := &Reconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}
	if err := reconciler.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("failed to create Tetragon daemon set reconciler: %w", err)
	}

	if err := createServiceMonitors(ctx, log, reconciler.Client, cfg.TetragonNamespace, opCM); err != nil {
		return fmt.Errorf("failed to create Tetragon ServiceMonitors: %w", err)
	}

	go func() {
		if err := mgr.Start(ctx); err != nil {
			panic(fmt.Errorf("reconciler Tetragon daemon set manager failed: %w", err))
		}
		//TODO (FGI): handle graceful termination through context
	}()
	return nil
}

func getK8SClient(kubeconfigPath string) (*kubernetes.Clientset, error) {
	restConfig, err := getConfig(kubeconfigPath)
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

func getConfig(kubeconfigPath string) (*rest.Config, error) {
	if kubeconfigPath != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	}
	return rest.InClusterConfig()
}

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(v1alpha1.AddToScheme(scheme))
	utilruntime.Must(monitoringv1.AddToScheme(scheme))
}
