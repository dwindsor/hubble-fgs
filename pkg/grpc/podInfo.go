package grpc

import (
	"net"

	v1 "github.com/cilium/hubble/pkg/api/v1"
	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/pkg/filters"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
	coreV1 "k8s.io/api/core/v1"
)

func getExecCommand(probe *coreV1.Probe) []string {
	if probe != nil && probe.Exec != nil {
		return probe.Exec.Command
	}
	return nil
}

func (pm *ProcessManager) getPodInfoOfIp(ip net.IP) *fgs.Pod {
	ipcacheEntry, ok := pm.ciliumState.GetIPCache().GetIPIdentity(ip)
	if !ok {
		return nil
	}
	return &fgs.Pod{
		Namespace: ipcacheEntry.Namespace,
		Name:      ipcacheEntry.PodName,
		Labels:    nil,
		Container: nil,
	}
}

func getProbes(pod *coreV1.Pod, containerStatus *coreV1.ContainerStatus) ([]string, []string) {
	for _, container := range pod.Spec.Containers {
		if container.Name == containerStatus.Name {
			return getExecCommand(container.LivenessProbe), getExecCommand(container.ReadinessProbe)
		}
	}
	return nil, nil
}

func (pm *ProcessManager) getPodInfo(containerID string, binary string, args string, nspid uint32) (*fgs.Pod, *v1.Endpoint) {
	if containerID == "" {
		return nil, nil
	}
	pod, container, ok := pm.watcher.FindPod(containerID)
	if !ok {
		pm.log.WithField("container id", containerID).Trace("failed to get pod")
		return nil, nil
	}
	var startTime *timestamppb.Timestamp
	livenessProbe, readinessProbe := getProbes(pod, container)
	maybeExecProbe := filters.MaybeExecProbe(binary, args, livenessProbe) ||
		filters.MaybeExecProbe(binary, args, readinessProbe)
	if container.State.Running != nil {
		startTime = timestamppb.New(container.State.Running.StartedAt.Time)
	}
	endpoint, ok := pm.ciliumState.GetEndpointsHandler().GetEndpointByPodName(pod.Namespace, pod.Name)
	var labels []string
	if ok {
		labels = endpoint.Labels
	}

	// Don't set container PIDs if it's zero.
	var containerPID *wrapperspb.UInt32Value
	if nspid > 0 {
		containerPID = &wrapperspb.UInt32Value{
			Value: nspid,
		}
	}
	return &fgs.Pod{
		Namespace: pod.Namespace,
		Name:      pod.Name,
		Labels:    labels,
		Container: &fgs.Container{
			Id:   container.ContainerID,
			Pid:  containerPID,
			Name: container.Name,
			Image: &fgs.Image{
				Id:   container.ImageID,
				Name: container.Image,
			},
			StartTime:      startTime,
			MaybeExecProbe: maybeExecProbe,
		},
	}, endpoint
}
