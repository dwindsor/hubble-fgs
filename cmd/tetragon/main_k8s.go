//go:build !nok8s

package tetragon

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/lumberjack/v2"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
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

func initK8s(ctx context.Context, alertsManager alerts.RuleManager) error {
	var err error
	kubernetesManager := manager.Get()

	// Initialize a k8s watcher used to manage policies. This should happen
	// after the sensors are loaded, otherwise existing policies will fail to
	// load on the first attempt.
	if enterpriseOption.K8SControlPlaneEnabled() {
		log.Info("Enabling policy watcher")

		// add informers for all resources
		if enterpriseOption.Config.EnablePolicyK8sWatcher {
			// NB(anna): Check this option for OSS compatibility, but it's not
			// recommended to use it to disable watching TracingPolicy in EE.
			// Use --enable-policy-k8swatcher=false instead.
			if option.Config.EnableTracingPolicyCRD {
				err = crdwatcher.AddTracingPolicyInformer(ctx, kubernetesManager.GetControllerManager(), observer.GetSensorManager())
				if err != nil {
					return err
				}
			}
			if enterpriseOption.Config.EnableSandboxPolicies {
				err = enterpriseWatcher.AddSandboxPolicyInformer(ctx, kubernetesManager.GetControllerManager(), observer.GetSensorManager())
				if err != nil {
					return err
				}
			}
			if enterpriseOption.Config.EnableAlerts {
				err = enterpriseWatcher.AddAlertRuleInformer(ctx, kubernetesManager.GetControllerManager(), alertsManager)
				if err != nil {
					return err
				}
			}
			if enterpriseOption.Config.EnableApplicationModel {
				err = netpol.AddTetragonNetworkPolicyInformer(ctx, kubernetesManager.GetControllerManager())
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func initK8sMetrics() {
	go enterpriseMetrics.StartPodDeleteHandler()
	// Handler must be registered before the watcher is started
	metrics.RegisterPodDeleteHandler()
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
	var flatWriter *lumberjack.Logger
	var writer *lumberjack.Logger
	var connectionWriter *lumberjack.Logger
	var err error

	if enterpriseOption.Config.ApplicationModelExportFilename != "" {
		writer, err = getWriter(
			enterpriseOption.Config.ApplicationModelExportFilename,
			option.Config.ExportFileMaxSizeMB,
			option.Config.ExportFileMaxBackups,
			option.Config.ExportFileCompress,
		)
		if err != nil {
			return err
		}
	}

	if enterpriseOption.Config.TelemetryExportFilename != "" {
		flatWriter, err = getWriter(
			enterpriseOption.Config.TelemetryExportFilename,
			option.Config.ExportFileMaxSizeMB,
			option.Config.ExportFileMaxBackups,
			option.Config.ExportFileCompress,
		)
		if err != nil {
			return err
		}
	}
	if enterpriseOption.Config.ConnectionLogFileName != "" {
		connectionWriter, err = getWriter(
			enterpriseOption.Config.ConnectionLogFileName,
			option.Config.ExportFileMaxSizeMB,
			option.Config.ExportFileMaxBackups,
			option.Config.ExportFileCompress,
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
