// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package dnsparser

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/cgroups"
	"github.com/cilium/tetragon/pkg/cgroups/fsscan"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// requeueTiming is the wait time between reconciliation retry when we find a
// new Pod that wasn't linked to a DNS state yet.
const requeueTiming = 1 * time.Minute

type allocID = uint32

type fsPodScanner interface {
	FindPodPath(podID types.UID) (string, error)
}

type PodStore struct {
	// Can't use the UUID as key because of how deletion works in reconciliation
	pods  map[types.NamespacedName]allocID
	mutex sync.RWMutex
}

func (s *PodStore) Delete(name types.NamespacedName) {
	s.mutex.Lock()
	delete(s.pods, name)
	s.mutex.Unlock()
}

func (s *PodStore) Lookup(name types.NamespacedName) (allocID uint32, exist bool) {
	s.mutex.RLock()
	allocID, exist = s.pods[name]
	s.mutex.RUnlock()
	return
}

func (s *PodStore) Store(name types.NamespacedName, allocID allocID) {
	s.mutex.Lock()
	s.pods[name] = allocID
	s.mutex.Unlock()
}

type PodReconciler struct {
	client.Client

	// This is the current set of local Pods watched by the controller
	podStore PodStore

	// The fsscaner and the cgroup ID to alloc ID map are used to make the
	// link between the Pod UUID from the API, the cgroup path, thus cgroup
	// ID and thus the allocation ID.
	fsScaner         fsPodScanner
	cgidToAllocIDMap CgroupIDToAllocIDMap

	// ipToIDMaps is the state the controller will manage, adding or
	// removing new inner maps by watching the local Pods
	ipToIDMaps IPToIDMaps
	// allocationIDMap is to read the current allocationID (and thus know
	// how many maps we are currently using)
	allocationIDMap AllocationIDMap
}

// NewPodReconciler takes ipToIDMaps as input instead of recreating that object
// because this wrapper is stateful and needs to be shared across execution.
func NewPodReconciler(client client.Client, ipToIDMaps IPToIDMaps) (PodReconciler, error) {
	cgidToAllocIDFile := filepath.Join(bpf.MapPrefixPath(), CgroupIDToAllocIDMapName)
	cgidToAllocIDRaw, err := ebpf.LoadPinnedMap(cgidToAllocIDFile, nil)
	if err != nil {
		return PodReconciler{}, fmt.Errorf("failed to load %q map: %w", cgidToAllocIDFile, err)
	}

	allocationIDFile := filepath.Join(bpf.MapPrefixPath(), AllocationIDMapName)
	allocationIDRaw, err := ebpf.LoadPinnedMap(allocationIDFile, nil)
	if err != nil {
		return PodReconciler{}, fmt.Errorf("failed to load %q map: %w", allocationIDFile, err)
	}

	return PodReconciler{
		Client: client,

		podStore: PodStore{
			pods:  map[types.NamespacedName]allocID{},
			mutex: sync.RWMutex{},
		},

		fsScaner:         fsscan.New(),
		cgidToAllocIDMap: NewCgroupIDToAllocIDMap(cgidToAllocIDRaw),

		ipToIDMaps:      ipToIDMaps,
		allocationIDMap: NewAllocationIDMap(allocationIDRaw),
	}, nil
}

func (r *PodReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Pod{}).
		Complete(r)
}

func AllocateMapsIfNeeded(ipToIDMaps *IPToIDMaps, allocID uint32) error {
	// The number of free maps is the number of allocated maps (which
	// accounts for removed maps) - the current alloc ID + 1.
	mapUsed := allocID + 1
	freeMaps := int(ipToIDMaps.MapCount()) - int(mapUsed)
	if freeMaps < int(IPToIDMapsMargin) {
		for range int(IPToIDMapsMargin) - freeMaps {
			err := ipToIDMaps.AppendAndPopulateNewInnerMap()
			if err != nil {
				return fmt.Errorf("failed allocating new map: %w", err)
			}
		}
	}
	return nil
}

func GetCgroupIDFromPodUID(uid types.UID, fsScaner fsPodScanner) (uint64, error) {
	podDir, err := fsScaner.FindPodPath(uid)
	if err != nil {
		return 0, fmt.Errorf("failed to find the Pod %s cgroup path: %w", uid, err)
	}
	if podDir == "" {
		// Pods from which we can't find the cgroup path might be static pods, let's ignore them
		return 0, nil
	}
	// From that we get the cgroup ID
	cgroupID, err := cgroups.GetCgroupIdFromPath(podDir)
	if err != nil {
		return 0, fmt.Errorf("failed getting the cgroup ID from the cgroup directory %s: %w", podDir, err)
	}
	return cgroupID, nil
}

// The Reconcile loop is divided into two steps with separate goals managing the
// ipToIDMaps.
//
// First is to allocate more maps if needed, for that we just need to read the
// current allocation ID used by the datapath and compare with the number of
// existing maps.
//
// Second is to track the link between the Pods and their potential DNS state
// (if they had DNS activity: e.g. you can have 10 pods with only 5 DNS states
// if only 5 did network queries) to garbage collect the unusued inner maps.
func (r *PodReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// Do we need to allocate more maps?
	currentAllocID, err := r.allocationIDMap.Value()
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to lookup the current allocation ID: %w", err)
	}
	err = AllocateMapsIfNeeded(&r.ipToIDMaps, currentAllocID)
	if err != nil {
		return ctrl.Result{}, err
	}

	var pod corev1.Pod
	if err := r.Get(ctx, req.NamespacedName, &pod); err != nil {
		if apierrors.IsNotFound(err) {
			// Pod has been deleted
			allocID, exist := r.podStore.Lookup(req.NamespacedName)
			if !exist {
				// This shouldn't happen ideally but let's ignore it
				return ctrl.Result{}, nil
			}

			err := r.ipToIDMaps.RemoveInnerMap(allocID)
			if err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to remove inner map: %w", err)
			}

			r.podStore.Delete(req.NamespacedName)

			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Check if pod is already known
	if _, exist := r.podStore.Lookup(req.NamespacedName); exist {
		return ctrl.Result{}, nil
	}

	// New Pod, let's find the cgroup ID to see if we have an associated alloc ID
	cgroupID, err := GetCgroupIDFromPodUID(pod.GetUID(), r.fsScaner)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to get cgroup ID from Pod UID: %w", err)
	}
	allocID, err := r.cgidToAllocIDMap.Lookup(cgroupID)
	if err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			// Maybe the Pod didn't make any DNS queries yet, let's retry later
			return ctrl.Result{RequeueAfter: requeueTiming}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to lookup allocation ID: %w", err)
	}

	r.podStore.Store(req.NamespacedName, allocID)

	return ctrl.Result{}, nil
}
