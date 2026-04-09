//go:build nok8s

package layer3

import (
	"net"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

func destK8sInfo(destinationIP net.IP) (*tetragon.Pod, *tetragon.Service) {
	return nil, nil
}
