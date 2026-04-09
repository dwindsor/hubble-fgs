//go:build nok8s

package podinfo

import (
	"net"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

func GetPodInfoOfIp(ip net.IP) *tetragon.Pod {
	return nil
}
