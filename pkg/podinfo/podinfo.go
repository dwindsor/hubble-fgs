package podinfo

import (
	"net"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/cilium"
	"github.com/isovalent/hubble-fgs/pkg/manager"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	coreV1 "k8s.io/api/core/v1"
)

func getExecCommand(probe *coreV1.Probe) []string {
	if probe != nil && probe.Exec != nil {
		return probe.Exec.Command
	}
	return nil
}

func GetPodInfoOfIp(ip net.IP) *tetragon.Pod {
	if option.Config.EnablePodInfo {
		return getPodInfoOfIpFromPodInfo(ip)
	} else if enterpriseOption.Config.EnableCilium {
		return getPodInfoOfIpFromCilium(ip)
	}
	return nil
}

func getPodInfoOfIpFromCilium(ip net.IP) *tetragon.Pod {
	ciliumState := cilium.GetCiliumState()
	ipcacheEntry, ok := ciliumState.GetIPCache().GetIPIdentity(ip)
	if !ok {
		return nil
	}
	return &tetragon.Pod{
		Namespace: ipcacheEntry.Namespace,
		Name:      ipcacheEntry.PodName,
		Container: nil,
	}
}

func getPodInfoOfIpFromPodInfo(ip net.IP) *tetragon.Pod {
	pods, err := manager.Get().FindPodInfoByIP(ip.String())
	if err != nil || len(pods) != 1 {
		return nil
	}
	return &tetragon.Pod{
		Namespace:    pods[0].Namespace,
		Name:         pods[0].Name,
		PodLabels:    pods[0].Labels,
		Workload:     pods[0].WorkloadObject.Name,
		WorkloadKind: pods[0].WorkloadType.Kind,
	}
}

func GetProbes(pod *coreV1.Pod, containerStatus *coreV1.ContainerStatus) ([]string, []string) {
	for _, container := range pod.Spec.Containers {
		if container.Name == containerStatus.Name {
			return getExecCommand(container.LivenessProbe), getExecCommand(container.ReadinessProbe)
		}
	}
	return nil, nil
}

func GetPodInfoOfNS(namespace string) ([]v1alpha1.PodInfo, error) {
	return manager.Get().GetPodInfoOfNS(namespace)
}
