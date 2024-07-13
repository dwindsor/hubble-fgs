package svcinfo

import (
	"net"

	"github.com/cilium/tetragon/api/v1/tetragon"
	oss "github.com/cilium/tetragon/pkg/watcher"

	"github.com/isovalent/hubble-fgs/pkg/watcher"
)

var (
	k8sResourceWatcher oss.K8sResourceWatcher
)

func SetK8sResourceWatcher(watcher oss.K8sResourceWatcher) {
	k8sResourceWatcher = watcher
}

func GetSvcInfoOfIp(ip net.IP) *tetragon.Service {
	if k8sResourceWatcher == nil {
		return nil
	}
	k8sDestinationServices, err := watcher.FindServiceByIP(k8sResourceWatcher, ip.String())
	if err != nil {
		return nil
	}

	return &tetragon.Service{
		Name:      k8sDestinationServices[0].Name,
		Namespace: k8sDestinationServices[0].Namespace,
	}
}
