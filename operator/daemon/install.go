// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package daemon

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/operator/option"
	"github.com/cilium/tetragon/pkg/k8s/version"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/isovalent/hubble-fgs/operator/options"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "tetragon-daemon")

func InstallTetragonDaemonSet() error {
	restConfig, err := getConfig()
	if err != nil {
		log.WithError(err).Fatal("Unable to check k8s configuration")
	}

	k8sClient, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		log.WithError(err).Fatal("Unable to create k8s client")
	}

	if err := version.UpdateK8sServerVersion(k8sClient); err != nil {
		log.WithError(err).Fatal("Unable to check k8s version")
	}

	ctx := context.Background()

	exists, err := isDaemonSetExists(ctx, k8sClient)
	if err != nil {
		return fmt.Errorf("failed to get tetragon daemon set: %s", err)
	}
	if exists {
		log.Info("tetragon daemon set already exists, skip installation")
		return nil
	}

	log.Infof("installing tetragon daemon set: %s", options.Config.DaemonSetName)
	if err := createDaemonSet(ctx, k8sClient); err != nil {
		return fmt.Errorf("failed to install tetragon daemon set: %s", err)
	}
	log.Info("tetragon daemon set installation completed")
	return nil
}

func getConfig() (*rest.Config, error) {
	if option.Config.KubeCfgPath != "" {
		return clientcmd.BuildConfigFromFlags("", option.Config.KubeCfgPath)
	}
	return rest.InClusterConfig()
}
