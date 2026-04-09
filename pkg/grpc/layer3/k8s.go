//go:build !nok8s

package layer3

import (
	"net"

	"github.com/cilium/tetragon/api/v1/tetragon"

	"github.com/isovalent/hubble-fgs/pkg/manager"
	"github.com/isovalent/hubble-fgs/pkg/podinfo"
)

func destK8sInfo(destinationIP net.IP) (*tetragon.Pod, *tetragon.Service) {
	dstPod := podinfo.GetPodInfoOfIp(destinationIP)
	dstService := manager.Get().GetSvcInfoOfIp(destinationIP)
	return dstPod, dstService
}
