// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build !nok8s

package layer3

import (
	"fmt"

	"github.com/cilium/tetragon/pkg/rthooks"

	"github.com/isovalent/hubble-fgs/pkg/dnsparser"
	"github.com/isovalent/hubble-fgs/pkg/manager"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	"github.com/isovalent/hubble-fgs/pkg/workloadid"
)

func init() {
	// rthooks register callbacks can only be called at init, so we need to
	// register this even if the application model is not enabled unfortunately
	rthooks.RegisterCallbacksAtInit(rthooks.Callbacks{
		CreateContainer: workloadid.GetState().CreateContainerHook,
	})
}

func enableBPFDnsPerPod(ipToIDMaps dnsparser.IPToIDMaps) error {
	controllerManager := manager.Get().GetControllerManager()
	// Start the reconciler only if there is a k8s control plane
	if controllerManager != nil {
		m := controllerManager.Manager
		reconciler, err := dnsparser.NewPodReconciler(m.GetClient(), &ipToIDMaps)
		if err != nil {
			return fmt.Errorf("failed to create a new Pod reconciler for the DNS parser per Pod feature: %w", err)
		}
		if err = reconciler.SetupWithManager(m); err != nil {
			return fmt.Errorf("failed to setup the Pod reconciler for the DNS parser per Pod feature: %w", err)
		}
	}

	return nil
}

// This probably shouldn't be here, but there doesn't seem to be a hook in the
// base sensor for after the bpf programs have been loaded and the maps have
// been created?
func setupWorkloadID() error {
	// Initialize the workloadid state with the BPF map so it can be
	// used even without a K8s control plane (e.g. in tests). We
	// have already registered the hook for the container creation
	// at init, we need to enable the hook by wiring the BPF map.
	err := workloadid.GetState().SetMap(base.CgroupIDToWorkloadIDMap.MapHandle)
	if err != nil {
		return fmt.Errorf("failed to set workload ID map with %s: %w", base.CgroupIDToWorkloadIDMap.Name, err)
	}

	// Start the reconciler only if there is a k8s control plane
	controllerManager := manager.Get().GetControllerManager()
	if controllerManager != nil {
		if err := workloadid.GetState().SetupWithManager(controllerManager.Manager); err != nil {
			return fmt.Errorf("failed to setup the state ID reconciler for the application model: %w", err)
		}
	}

	return nil
}
