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
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	oss "github.com/cilium/tetragon/pkg/testutils/policytest"
	"github.com/cilium/tetragon/pkg/tetragoninfo"

	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
)

func TestSwitchesForCLIFlags(t *testing.T) {
	flags := []oss.CLIFlag{
		{Name: "enable-udp", Value: true},
		{Name: "udp-stats-interval", Value: 2 * time.Second},
		{Name: "udp-idle-socket-timeout", Value: time.Minute},
		{Name: "multicast-app", Value: "RTP"},
		{Name: "enable-user-dns", Value: true},
		{Name: "dns-ports", Value: []int{53}},
		{Name: "enable-tls-sensor", Value: true},
		{Name: "tls-sensor-mode", Value: "socket"},
		{Name: "tls-sensor-ports", Value: []int{443}},
		{Name: "enable-http-sensor", Value: true},
		{Name: "http-sensor-ports", Value: []int{80}},
	}

	switches, err := switchesForCLIFlags(flags)
	require.NoError(t, err)
	require.Len(t, switches, 13)
	require.Equal(t, &enterpriseOption.Config.EnableUDP, switches[0].KeyPtr)
	require.Equal(t, 2*time.Second, switches[1].Value)
	require.Equal(t, &enterpriseOption.Config.UDPIdleSocketTimeout, switches[2].KeyPtr)
	require.Equal(t, time.Minute, switches[2].Value)
	require.Equal(t, enterpriseOption.MulticastAppRTP, switches[3].Value)
	require.Equal(t, &enterpriseOption.Config.MulticastApp, switches[4].KeyPtr)
	require.Equal(t, &enterpriseOption.Config.EnableUserDNS, switches[5].KeyPtr)
	require.Equal(t, &enterpriseOption.Config.DNSPorts, switches[6].KeyPtr)
	require.Equal(t, &enterpriseOption.Config.EnableTLSSensor, switches[7].KeyPtr)
	require.Equal(t, &enterpriseOption.Config.TLSSensorMode, switches[8].KeyPtr)
	require.Equal(t, &enterpriseOption.Config.TLSSensorPorts, switches[9].KeyPtr)
	require.Equal(t, &enterpriseOption.Config.EnableHTTPSensor, switches[10].KeyPtr)
	require.Equal(t, &enterpriseOption.Config.HTTPSensorPorts, switches[11].KeyPtr)
	require.Equal(t, &enterpriseOption.Config.Layer3CLIEnable, switches[12].KeyPtr)
}

func TestAgentInfoWithCLIFlags(t *testing.T) {
	info := &tetragoninfo.Info{Conf: map[string]any{"enable-tcp": false}}
	actual := agentInfoWithCLIFlags(info, []oss.CLIFlag{
		{Name: "enable-tcp", Value: true},
		{Name: "udp-stats-interval", Value: 2 * time.Second},
	})

	require.False(t, info.Conf["enable-tcp"].(bool))
	require.True(t, actual.Conf["enable-tcp"].(bool))
	require.Equal(t, 2*time.Second, actual.Conf["udp-stats-interval"])
}
