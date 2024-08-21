//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package file

import (
	"context"
	"sync"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/rthooks"
	"github.com/google/uuid"
	"github.com/isovalent/hubble-fgs/pkg/metrics/filemetrics"
	fm "github.com/isovalent/hubble-fgs/pkg/sensors/file/utils"
	v1 "k8s.io/api/core/v1"
)

type ContInit struct {
	cid, namespace, name, root string
}

type ContData struct {
	ContainerID string // it contains a prefix if this comes from k8s watcher, if it comes from rthooks it does not
	RootDir     string // if ContainerID has a prefix (i.e. docker/containerd) the rootDir should be ""
}

type PodInfo struct {
	podName      string
	podNamespace string
	podUUID      uuid.UUID
	containers   map[string]ContData // key is containerID (does not contain the prefix)
}

func (p *PodInfo) AddContainer(cid, root string) {
	c := fm.RemoveContainerIdPrefix(cid)
	p.containers[c] = ContData{
		ContainerID: cid,
		RootDir:     root,
	}
}

func (p *PodInfo) LookupContainer(cid string) bool {
	c := fm.RemoveContainerIdPrefix(cid)
	_, ok := p.containers[c]
	return ok
}

func (p *PodInfo) DelContainer(cid string) {
	c := fm.RemoveContainerIdPrefix(cid)
	delete(p.containers, c)
}

var (
	allPods   = make(map[string]*PodInfo) // key is Pod UUID
	allPodsMu sync.Mutex                  // protects allPods
)

func podForAllContainersId(pod *v1.Pod, fn func(id string)) {
	run := func(s []v1.ContainerStatus) {
		for _, i := range s {
			if i.State.Running != nil {
				fn(i.ContainerID)
			}
		}
	}

	run(pod.Status.InitContainerStatuses)
	run(pod.Status.ContainerStatuses)
	run(pod.Status.EphemeralContainerStatuses)
}

func podContainersIDs(pod *v1.Pod) []string {
	ret := make([]string, 0)
	podForAllContainersId(pod, func(id string) {
		ret = append(ret, id)
	})
	return ret
}

// podContainerDiff compares the containers of two pods (old and new) and
// returns the container ids that were added and the container ids that were
// deleted.
func podContainerDiff(oldPod *v1.Pod, newPod *v1.Pod) ([]string, []string) {
	oldNr := len(oldPod.Status.ContainerStatuses)
	newNr := len(newPod.Status.ContainerStatuses)
	allIDs := make(map[string]struct{}, oldNr+newNr)

	oldIDs := make(map[string]struct{}, oldNr)
	podForAllContainersId(oldPod, func(id string) {
		oldIDs[id] = struct{}{}
		allIDs[id] = struct{}{}
	})

	newIDs := make(map[string]struct{}, newNr)
	podForAllContainersId(newPod, func(id string) {
		newIDs[id] = struct{}{}
		allIDs[id] = struct{}{}
	})

	addContIDs := []string{}
	delContIDs := []string{}
	for cID := range allIDs {
		if _, ok := oldIDs[cID]; !ok {
			// in the new, but not in the old
			addContIDs = append(addContIDs, cID)
		} else if _, ok := newIDs[cID]; !ok {
			// in the old, but not in the new
			delContIDs = append(delContIDs, cID)
		}
	}

	return addContIDs, delContIDs
}

func rthooksCreateContainer(_ context.Context, arg *rthooks.CreateContainerArg) error {
	containerID, err := arg.ContainerID()
	if err != nil {
		logger.GetLogger().WithError(err).Warn("failed to retrieve container id, aborting hook")
		return err
	}

	podIDstr, err := arg.PodID()
	if err != nil {
		logger.GetLogger().WithError(err).Warn("failed to retrieve pod id, aborting hook")
		return err
	}

	pod, err := arg.Pod()
	if err != nil {
		logger.GetLogger().WithError(err).Warn("failed to get pod info, aborting hook.")
		filemetrics.FileTotalErrorsInc(filemetrics.SensorFileGetPodInfo)
		return err
	}

	initNeeded := false // do we need to call TracingPolicyInitContainerFsScanner?

	allPodsMu.Lock()
	if m, ok := allPods[podIDstr]; ok {
		// if the container ID already exists there is nothing more to do
		if !m.LookupContainer(containerID) {
			m.AddContainer(containerID, arg.Req.RootDir)
			initNeeded = true
		}
	} else {
		// we expect to have the pod created here
		logger.GetLogger().Warnf("fim: pod [%s] does not exists in our metadata during the call of rthooks.CreateContainer", pod.ObjectMeta.Name)
	}
	allPodsMu.Unlock()

	// we just need to update our internal data structures
	// fs-scanner is not started yet (i.e. no fim tracing policies yet)
	if fsScannerCmd == nil {
		return nil
	}

	if !initNeeded {
		return nil
	}

	_, err = TracingPolicyInitContainerFsScanner([]fm.SpecPinPath{}, containerID, pod.ObjectMeta.Namespace, pod.ObjectMeta.Name, arg.Req.RootDir, true)
	return err
}

func podhooksAddFunc(obj interface{}) {
	pod, ok := obj.(*v1.Pod)
	if !ok {
		logger.GetLogger().Warn("fim, add-pod handler: unexpected object type: %T", pod)
		return
	}

	podID, err := uuid.Parse(string(pod.UID))
	if err != nil {
		logger.GetLogger().WithField("pod-id", pod.UID).WithError(err).Warn("fim, add-pod handler: failed to parse pod id")
		return
	}

	newCIDs := []string{} // need to call TracingPolicyInitContainerFsScanner on these
	addedIDs := podContainersIDs(pod)

	allPodsMu.Lock()
	if _, ok := allPods[podID.String()]; ok {
		logger.GetLogger().Warnf("fim: pod [%s] already exists in our metadata", pod.Name)
	} else {
		d := PodInfo{
			podName:      pod.Name,
			podNamespace: pod.Namespace,
			podUUID:      podID,
			containers:   make(map[string]ContData),
		}

		for _, c := range addedIDs {
			// no need to check if they alredy exist as we now create the pod
			d.AddContainer(c, "")
			newCIDs = append(newCIDs, c)
		}

		allPods[podID.String()] = &d
	}
	allPodsMu.Unlock()

	// we just need to update our internal data structures
	// fs-scanner is not started yet (i.e. no fim tracing policies yet)
	if fsScannerCmd == nil {
		return
	}

	for _, c := range newCIDs {
		if _, err := TracingPolicyInitContainerFsScanner([]fm.SpecPinPath{}, c, pod.Namespace, pod.Name, "", true); err != nil {
			filemetrics.FileTotalErrorsInc(filemetrics.SensorFileInitPodAddScanner)
			logger.GetLogger().WithError(err).Warnf("add: TracingPolicyInitContainerFsScanner failed")
		}
	}
}

func podhooksUpdateFunc(oldObj, newObj interface{}) {
	pod1, ok1 := oldObj.(*v1.Pod)
	pod2, ok2 := newObj.(*v1.Pod)
	if !ok1 || !ok2 {
		logger.GetLogger().Warn("fim, update-pod: unexpected object type(s): old:%T new:%T", pod1, pod2)
		return
	}
	if pod1.UID != pod2.UID {
		logger.GetLogger().Warn("fim, update-pod: unexpected pod ids: old:%T new:%T", pod1.UID, pod2.UID)
		return
	}
	if pod1.Name != pod2.Name {
		logger.GetLogger().Warn("fim, update-pod: unexpected pod name: old:%s new:%s", pod1.Name, pod2.Name)
		return
	}
	if pod1.Namespace != pod2.Namespace {
		logger.GetLogger().Warn("fim, update-pod: unexpected pod namespaces: old:%s new:%s", pod1.Namespace, pod2.Namespace)
		return
	}

	podID, err := uuid.Parse(string(pod1.UID))
	if err != nil {
		logger.GetLogger().WithField("pod-id", pod1.UID).WithError(err).Warn("fim, update-pod: failed to parse id")
		return
	}

	newCIDs := []string{} // need to call TracingPolicyInitContainerFsScanner on these
	delCIDs := []string{} // need to call TracingPolicyDestroyContainerFsScanner on these
	addedIDs, deletedIDs := podContainerDiff(pod1, pod2)

	allPodsMu.Lock()
	if m, ok := allPods[podID.String()]; ok {
		for _, c := range addedIDs {
			found := m.LookupContainer(c)
			m.AddContainer(c, "") // always update the root path, the previous may not be available
			if !found {           // call TracingPolicyInitContainerFsScanner only once, we may have called that in rthooks.CreateContainer
				newCIDs = append(newCIDs, c)
			}
		}
		for _, c := range deletedIDs {
			if m.LookupContainer(c) { // no need to delete anything if container does not exist
				m.DelContainer(c)
				delCIDs = append(delCIDs, c)
			}
		}
	} else {
		logger.GetLogger().Warnf("fim: pod [%s] does not exist in our metadata during update", pod1.Name)
	}
	allPodsMu.Unlock()

	// we just need to update our internal data structures
	// fs-scanner is not started yet (i.e. no fim tracing policies yet)
	if fsScannerCmd == nil {
		return
	}

	for _, c := range delCIDs {
		if err := TracingPolicyDestroyContainerFsScanner(c); err != nil {
			filemetrics.FileTotalErrorsInc(filemetrics.SensorFileDestroyPodUpdateScanner)
			logger.GetLogger().WithError(err).Warnf("update: TracingPolicyDestroyContainerFsScanner failed")
		}
	}
	for _, c := range newCIDs {
		if _, err := TracingPolicyInitContainerFsScanner([]fm.SpecPinPath{}, c, pod1.Namespace, pod1.Name, "", true); err != nil {
			filemetrics.FileTotalErrorsInc(filemetrics.SensorFileInitPodUpdateScanner)
			logger.GetLogger().WithError(err).Warnf("update: TracingPolicyInitContainerFsScanner failed")
		}
	}
}

func podhooksDeleteFunc(obj interface{}) {
	pod, ok := obj.(*v1.Pod)
	if !ok {
		logger.GetLogger().Warn("fim, add-pod handler: unexpected object type: %T", pod)
		return
	}

	podID, err := uuid.Parse(string(pod.UID))
	if err != nil {
		logger.GetLogger().WithField("pod-id", pod.UID).WithError(err).Warn("fim, add-pod handler: failed to parse pod id")
		return
	}

	delCIDs := []string{} // need to call TracingPolicyDestroyContainerFsScanner on these
	deletedIDs := podContainersIDs(pod)

	allPodsMu.Lock()
	if m, ok := allPods[podID.String()]; ok {
		for _, c := range deletedIDs {
			if m.LookupContainer(c) { // no need to delete anything if container does not exist
				m.DelContainer(c)
				delCIDs = append(delCIDs, c)
			}
		}
	} else {
		logger.GetLogger().Warnf("fim: pod [%s] does not exist in our metadata during delete", pod.Name)
	}
	delete(allPods, podID.String()) // delete the pod from our metadata
	allPodsMu.Unlock()

	// we just need to update our internal data structures
	// fs-scanner is not started yet (i.e. no fim tracing policies yet)
	if fsScannerCmd == nil {
		return
	}

	for _, c := range delCIDs {
		if err := TracingPolicyDestroyContainerFsScanner(c); err != nil {
			filemetrics.FileTotalErrorsInc(filemetrics.SensorFileDestroyPodDeleteScanner)
			logger.GetLogger().WithError(err).Warnf("delete: TracingPolicyDestroyContainerFsScanner failed")
		}
	}
}
