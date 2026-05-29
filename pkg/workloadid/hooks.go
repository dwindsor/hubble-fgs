// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package workloadid

import (
	"context"
	"fmt"

	"github.com/cilium/tetragon/pkg/podhelpers"
	"github.com/cilium/tetragon/pkg/rthooks"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
)

func (s *State) SetupWithManager(mgr ctrl.Manager) error {
	s.Client = mgr.GetClient()
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Pod{}).
		Named("workloadid-pod").
		Complete(s)
}

func (s *State) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var pod corev1.Pod
	if err := s.Get(ctx, req.NamespacedName, &pod); err != nil {
		if apierrors.IsNotFound(err) {
			// Pod has been deleted
			// As per previous implementation[^1], we don't remove the mapping on deletion
			// [^1]: https://github.com/cilium/tetragon/commit/4e2c2fe66941f6afff6605f0c42d8b1371df9383
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// New Pod, let's find the cgroup ID to see if we have an associated alloc ID
	podCgroupID, err := s.cgroupIDResolver.GetPodCgroupID(pod.GetUID())
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to get cgroup ID from Pod: %w", err)
	}

	workloadMeta, workloadType := podhelpers.GetWorkloadMetaFromPod(&pod)

	wl := WorkloadMeta{
		Workload:  workloadMeta.Name,
		Namespace: pod.Namespace,
		Kind:      workloadType.Kind,
	}

	// BPF programs resolve cgroup IDs at the container level (not pod
	// level), collect all containers within this Pod cgroups IDs.
	cgroupIDs := []uint64{podCgroupID}
	containersCgroupIDs, err := s.cgroupIDResolver.GetContainersCgroupIDs(pod.GetUID())
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to get cgroup ID from containers: %w", err)
	}
	cgroupIDs = append(cgroupIDs, containersCgroupIDs...)

	for _, cgid := range cgroupIDs {
		err = s.Update(wl, CgroupID(cgid))
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to add to workload ID mapping: %w", err)
		}
	}

	return ctrl.Result{}, nil
}

func (s *State) CreateContainerHook(_ context.Context, arg *rthooks.CreateContainerArg) error {
	if s.cgroupIDToWorkloadIDMap == nil {
		// This means the state ID map has not been initialized yet
		return nil
	}

	cgroupID, err := arg.CgroupID()
	if err != nil {
		return fmt.Errorf("failed to get the cgroup ID: %w", err)
	}

	pod, err := arg.Pod()
	if err != nil {
		return fmt.Errorf("failed to get the Pod info: %w", err)
	}

	err = s.Update(WorkloadMeta{
		Workload:  pod.Name,
		Namespace: pod.Namespace,
		Kind:      pod.Kind,
	}, CgroupID(cgroupID))
	if err != nil {
		return fmt.Errorf("failed to add to state ID map: %w", err)
	}

	return nil
}
