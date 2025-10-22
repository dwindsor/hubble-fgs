package utils

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"
)

type Interface struct {
	Name             string   `json:"name"`
	Index            int      `json:"index"`
	Mtu              int      `json:"mtu"`
	HardwareAddr     string   `json:"hardwareAddress"`
	Flags            string   `json:"flags"`
	UnicastIpv4Ips   []string `json:"unicastIpv4Ips"`
	UnicastIpv6Ips   []string `json:"unicastIpv6Ips"`
	MulticastIpv4Ips []string `json:"multicastIpv4Ips"`
	MulticastIpv6Ips []string `json:"multicastIpv6Ips"`
}

// Get preferred outbound ip of this machine
func GetOutboundIP() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP.String(), nil
}

// Get all interfaces on the machine
func GetInterfaces() ([]Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var result []Interface
	for _, iface := range interfaces {
		uni_ips, err := iface.Addrs()
		if err != nil {
			uni_ips = []net.Addr{}
		}
		uniIpv4 := []string{}
		uniIpv6 := []string{}
		for _, ip := range uni_ips {
			ipObj := net.ParseIP(ip.String())
			if ipObj.To4() != nil {
				uniIpv4 = append(uniIpv4, ip.String())
			} else if ipObj.To16() != nil {
				uniIpv6 = append(uniIpv6, ip.String())
			}
		}

		multi_ips, err := iface.MulticastAddrs()
		if err != nil {
			multi_ips = []net.Addr{}
		}
		multiIpv4 := []string{}
		multiIpv6 := []string{}
		for _, ip := range multi_ips {
			ipObj := net.ParseIP(ip.String())
			if ipObj.To4() != nil {
				multiIpv4 = append(multiIpv4, ip.String())
			} else if ipObj.To16() != nil {
				multiIpv6 = append(multiIpv6, ip.String())
			}
		}

		result = append(result, Interface{
			Name:             iface.Name,
			Index:            iface.Index,
			Mtu:              iface.MTU,
			HardwareAddr:     iface.HardwareAddr.String(),
			Flags:            iface.Flags.String(),
			UnicastIpv4Ips:   uniIpv4,
			UnicastIpv6Ips:   uniIpv6,
			MulticastIpv4Ips: multiIpv4,
			MulticastIpv6Ips: multiIpv6,
		})
	}
	return result, nil
}

// GetDpuIP retrieves the IP addr from the specified interface with retry.
// It will retry with exponential backoff until the IP is found, the context is
// cancelled, or timeout (2 minutes) is exceeded. W/O a valid IP, the DPU cannot
// register with AGW.
// maxBackoff = 10 sec = maximum wait time between retry attempts
// maxWaitTime = 2 min = maximum total wait time

func GetDpuIP(ctx context.Context, ifname string) (string, error) {
	logger.GetLogger().Info("Getting DPU IP from interface", "interface", ifname)
	backoff := time.Second
	maxBackoff := 10 * time.Second
	maxWaitTime := 2 * time.Minute
	startTime := time.Now()

	for {
		// Try to get the IP from the interface
		intfs, err := net.Interfaces()
		if err != nil {
			return "", err
		}
		// Look for IP
		for _, intf := range intfs {
			if intf.Name != ifname {
				continue
			}
			addrs, err := intf.Addrs()
			if err != nil {
				return "", err
			}
			for _, addr := range addrs {
				ipnet, ok := addr.(*net.IPNet)
				if ok && ipnet.IP.To4() != nil {
					dpuIP := ipnet.IP.String()
					logger.GetLogger().Info("DPU IP obtained", "ip", dpuIP, "elapsed", time.Since(startTime))
					return dpuIP, nil
				}
			}
		}

		// IP not found yet
		elapsed := time.Since(startTime)

		// Check if we've exceeded the maximum wait time
		if elapsed > maxWaitTime {
			return "", errors.New("timeout waiting for DPU IP from interface " + ifname)
		}

		logger.GetLogger().Warn("Failed to get DPU IP, retrying",
			"interface", ifname,
			logfields.Error, errors.New("DPU IP not found"),
			"backoff : ", backoff,
			"elapsed : ", elapsed)

		// Wait for backoff duration or context cancellation
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(backoff):
			// Continue to next iteration
		}

		// Exponential backoff with max cap
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}
