// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build !windows

package policytest

import (
	"fmt"
	"maps"

	oss "github.com/cilium/tetragon/pkg/testutils/policytest"
	"github.com/cilium/tetragon/pkg/tetragoninfo"

	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	cli "github.com/isovalent/hubble-fgs/pkg/testutils/cliswitches"
)

func switchesForCLIFlags(flags []oss.CLIFlag) ([]cli.SwitchSettings, error) {
	switches := make([]cli.SwitchSettings, 0, len(flags)+1)
	layer3CLI := false
	for _, flag := range flags {
		var keyPtr any
		value := flag.Value
		switch flag.Name {
		case "enable-network-events":
			keyPtr = &enterpriseOption.Config.EnableNetworkEvents
		case "enable-tcp":
			keyPtr = &enterpriseOption.Config.EnableTCP
			layer3CLI = true
		case "enable-udp":
			keyPtr = &enterpriseOption.Config.EnableUDP
			layer3CLI = true
		case "enable-udp-cgroup":
			keyPtr = &enterpriseOption.Config.EnableUDPCGroup
		case "udp-stats-interval":
			keyPtr = &enterpriseOption.Config.UDPStatsInterval
		case "udp-idle-socket-timeout":
			keyPtr = &enterpriseOption.Config.UDPIdleSocketTimeout
		case "enable-icmp":
			keyPtr = &enterpriseOption.Config.EnableICMP
			layer3CLI = true
		case "enable-igmp":
			keyPtr = &enterpriseOption.Config.EnableIGMP
			layer3CLI = true
		case "enable-rawsock":
			keyPtr = &enterpriseOption.Config.EnableRawsock
			layer3CLI = true
		case "rawsock-report-close":
			keyPtr = &enterpriseOption.Config.RawsockReportClose
		case "enable-user-dns":
			keyPtr = &enterpriseOption.Config.EnableUserDNS
			layer3CLI = true
		case "dns-ports":
			keyPtr = &enterpriseOption.Config.DNSPorts
		case "enable-tls-sensor":
			keyPtr = &enterpriseOption.Config.EnableTLSSensor
		case "tls-sensor-mode":
			keyPtr = &enterpriseOption.Config.TLSSensorMode
		case "tls-sensor-ports":
			keyPtr = &enterpriseOption.Config.TLSSensorPorts
		case "enable-http-sensor":
			keyPtr = &enterpriseOption.Config.EnableHTTPSensor
		case "http-sensor-ports":
			keyPtr = &enterpriseOption.Config.HTTPSensorPorts
		case "multicast-app":
			keyPtr = &enterpriseOption.Config.MulticastApp
			appID, ok := map[string]enterpriseOption.MulticastAppID{"RTP": enterpriseOption.MulticastAppRTP}[flag.Value.(string)]
			if !ok {
				return nil, fmt.Errorf("unsupported --%s value %q", flag.Name, flag.Value)
			}
			switches = append(switches, cli.SwitchSettings{KeyPtr: &enterpriseOption.Config.MulticastAppID, Value: appID})
		case "multicast-ports":
			keyPtr = &enterpriseOption.Config.MulticastPorts
		case "enable-multicast-seq-check":
			keyPtr = &enterpriseOption.Config.MulticastSeqCheck
		case "multicast-sample-percent":
			keyPtr = &enterpriseOption.Config.MulticastSamplePercent
		default:
			return nil, fmt.Errorf("unsupported policytest CLI flag --%s", flag.Name)
		}
		switches = append(switches, cli.SwitchSettings{KeyPtr: keyPtr, Value: value})
	}
	if layer3CLI {
		switches = append(switches, cli.SwitchSettings{KeyPtr: &enterpriseOption.Config.Layer3CLIEnable, Value: true})
	}
	return switches, nil
}

func agentInfoWithCLIFlags(info *tetragoninfo.Info, flags []oss.CLIFlag) *tetragoninfo.Info {
	if info == nil {
		return nil
	}
	infoCopy := *info
	infoCopy.Conf = make(map[string]any, len(info.Conf)+len(flags))
	maps.Copy(infoCopy.Conf, info.Conf)
	for _, flag := range flags {
		infoCopy.Conf[flag.Name] = flag.Value
	}
	return &infoCopy
}
