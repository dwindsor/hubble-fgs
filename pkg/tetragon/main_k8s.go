//go:build !nok8s

package tetragon

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/manager/events"
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/watcher"
	"github.com/cilium/tetragon/pkg/watcher/crdwatcher"

	"github.com/isovalent/hubble-fgs/pkg/alerts"
	"github.com/isovalent/hubble-fgs/pkg/cilium"
	"github.com/isovalent/hubble-fgs/pkg/manager"
	enterpriseMetrics "github.com/isovalent/hubble-fgs/pkg/metrics"
	model "github.com/isovalent/hubble-fgs/pkg/model/server"
	"github.com/isovalent/hubble-fgs/pkg/netpol"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	enterpriseWatcher "github.com/isovalent/hubble-fgs/pkg/watcher"
)

func initK8s(alertsManager alerts.RuleManager) error {
	var err error
	kubernetesManager := manager.Get()

	// Initialize a k8s watcher used to manage policies. This should happen
	// after the sensors are loaded, otherwise existing policies will fail to
	// load on the first attempt.
	if enterpriseOption.K8SControlPlaneEnabled() {
		// controllerManager is non-nil here: Get() only returns a FakeManager
		// (with a nil controller manager) when the k8s control plane is
		// disabled, which the enclosing K8SControlPlaneEnabled() guard excludes.
		controllerManager := kubernetesManager.GetControllerManager()

		// Wire pod-event consumers that previously relied on the upstream
		// podhooks auto-install (removed in favour of events.PodEventSource).
		if err = wirePodEventConsumers(controllerManager.PodEvents()); err != nil {
			return err
		}

		log.Info("Enabling policy watcher")

		// Register CRD reconcilers. Each gates on its own CRD via
		// RegisterControllerWhenCRDReady, so cluster-scoped and namespaced
		// variants never block one another.
		if enterpriseOption.Config.EnablePolicyK8sWatcher {
			// NB(anna): Check this option for OSS compatibility, but it's not
			// recommended to use it to disable watching TracingPolicy in EE.
			// Use --enable-policy-k8swatcher=false instead.
			if option.Config.EnableTracingPolicyCRD {
				if err = crdwatcher.RegisterTracingPolicyReconciler(controllerManager, observer.GetSensorManager()); err != nil {
					return err
				}
				if err = crdwatcher.RegisterTracingPolicyNamespacedReconciler(controllerManager, observer.GetSensorManager()); err != nil {
					return err
				}
			}
			if enterpriseOption.Config.EnableSandboxPolicies {
				if err = enterpriseWatcher.RegisterSandboxPolicyReconciler(controllerManager, observer.GetSensorManager()); err != nil {
					return err
				}
				if err = enterpriseWatcher.RegisterSandboxPolicyNamespacedReconciler(controllerManager, observer.GetSensorManager()); err != nil {
					return err
				}
			}
			if enterpriseOption.Config.EnableAlerts {
				if err = enterpriseWatcher.RegisterAlertRuleReconciler(controllerManager, alertsManager); err != nil {
					return err
				}
			}
			if enterpriseOption.Config.EnableApplicationModel {
				if err = netpol.RegisterTetragonNetworkPolicyReconciler(controllerManager); err != nil {
					return err
				}
				// The namespaced reconciler is a placeholder until namespaced
				// support is implemented.
				if err = netpol.RegisterTetragonNetworkPolicyNamespacedReconciler(controllerManager); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// wirePodEventConsumers registers the pod-event consumers that previously
// relied on the upstream podhooks auto-install (manager.InstallHooks), removed
// in favour of an explicit events.PodEventSource. Each consumer is gated on its
// own enablement flag.
func wirePodEventConsumers(podEvents events.PodEventSource) error {
	if podEvents == nil {
		return nil
	}

	// Pod delete handler for metrics cleanup. Gated on MetricsServer: the
	// drainer (enterprise StartPodDeleteHandler, started in initK8sMetrics) only
	// runs when the metrics server is enabled, so registering unconditionally
	// would queue pod deletes that nothing drains.
	if option.Config.MetricsServer != "" {
		if err := metrics.RegisterPodDeleteHandler(podEvents); err != nil {
			return err
		}
	}

	// cgidmap and the file sensor (Linux-only host consumers).
	if err := enableHostPodHandlers(podEvents); err != nil {
		return err
	}

	if option.Config.EnablePolicyFilter {
		// A GetState failure is non-fatal here, mirroring the OSS wiring which
		// logs and continues rather than aborting startup. Use a distinct pfErr
		// so the intentional `return nil` is not misread as a dropped error.
		pfState, pfErr := policyfilter.GetState()
		if pfErr != nil {
			log.Warn("failed to get policyfilter state", logfields.Error, pfErr)
			return nil
		}
		if err := pfState.RegisterPodHandlers(podEvents); err != nil {
			return err
		}
	}

	return nil
}

func initK8sMetrics() {
	go enterpriseMetrics.StartPodDeleteHandler()
}

func k8sPodAccessor() watcher.PodAccessor {
	var podAccessor watcher.PodAccessor
	// Start Kubernetes manager. Note this doesn't have to be in the if block
	// below. If Kubernetes is not enabled, this call returns a fake manager.
	kubernetesManager := manager.Get()
	if enterpriseOption.K8SControlPlaneEnabled() && enterpriseOption.InClusterControlPlaneEnabled() {
		log.Info("Enabling Kubernetes API")
		podAccessor = kubernetesManager.GetControllerManager()
	} else {
		log.Info("Disabling Kubernetes API")
		podAccessor = watcher.NewFakeK8sWatcher(nil)
	}
	return podAccessor
}

func startApplicationModelExporter(ctx context.Context, modelServer *model.Server) error {
	var flatWriter *exportWriter
	var writer *exportWriter
	var connectionWriter *exportWriter
	var err error

	if enterpriseOption.Config.ApplicationModelExportFilename != "" {
		writer, err = getWriter(
			enterpriseOption.Config.ApplicationModelExportFilename,
			enterpriseOption.Config.ApplicationModelExportFileMaxSizeMB,
			enterpriseOption.Config.ApplicationModelExportFileMaxBackups,
			enterpriseOption.Config.ApplicationModelExportFileCompress,
			enterpriseOption.SplunkHECSourcetypeApplicationModel,
		)
		if err != nil {
			return err
		}
	}

	if enterpriseOption.Config.TelemetryExportFilename != "" {
		flatWriter, err = getWriter(
			enterpriseOption.Config.TelemetryExportFilename,
			enterpriseOption.Config.ApplicationModelExportFileMaxSizeMB,
			enterpriseOption.Config.ApplicationModelExportFileMaxBackups,
			enterpriseOption.Config.ApplicationModelExportFileCompress,
			enterpriseOption.SplunkHECSourcetypeTelemetry,
		)
		if err != nil {
			return err
		}
	}
	if enterpriseOption.Config.ConnectionLogFileName != "" {
		connectionWriter, err = getWriter(
			enterpriseOption.Config.ConnectionLogFileName,
			enterpriseOption.Config.ApplicationModelExportFileMaxSizeMB,
			enterpriseOption.Config.ApplicationModelExportFileMaxBackups,
			enterpriseOption.Config.ApplicationModelExportFileCompress,
			enterpriseOption.SplunkHECSourcetypeConnections,
		)
		if err != nil {
			return err
		}
	}

	if option.Config.ExportFileRotationInterval < 0 {
		// Passed an invalid interval let's error out
		return fmt.Errorf("frequency '%s' at which to rotate JSON export files is negative", option.Config.ExportFileRotationInterval.String())
	} else if option.Config.ExportFileRotationInterval > 0 {
		log.Info("Periodically rotating JSON application model export files", "frequency", option.Config.ExportFileRotationInterval.String())
		go func() {
			ticker := time.NewTicker(option.Config.ExportFileRotationInterval)
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if rotationErr := writer.Rotate(); rotationErr != nil {
						log.Warn("Failed to rotate JSON application model export file", logfields.Error, rotationErr,
							"file", enterpriseOption.Config.ApplicationModelExportFilename)
					}
				}
			}
		}()
	}

	go model.ExportApplicationModel(ctx, modelServer, writer, flatWriter, connectionWriter,
		enterpriseOption.Config.ApplicationModelExportInterval)

	return nil
}

func initCilumState(ctx context.Context) error {
	_, err := cilium.InitCiliumState(ctx, enterpriseOption.Config.EnableCilium)
	if err != nil {
		return fmt.Errorf("failed to init cilium state: %w", err)
	}
	return err
}
