//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package tcp

import (
	"bytes"
	"context"
	"encoding/binary"

	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/common"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/internal/ip"
)

var (
	baseTCPConnectPolicy = "__base_tcp_connect__"

	TCPConnect4 = program.Builder(
		"tcp_connect.sys",
		"cgroup/connect4",
		"tcp_connect4",
		"tcp::connect4",
		"windows",
	).SetPolicy(baseTCPConnectPolicy)

	TCPConnect6 = program.Builder(
		"tcp_connect.sys",
		"cgroup/connect6",
		"tcp_connect6",
		"tcp::connect6",
		"windows",
	).SetPolicy(baseTCPConnectPolicy)

	TCPAccept4 = program.Builder(
		"tcp_connect.sys",
		"cgroup/recv_accept4",
		"tcp_accept4",
		"tcp::accept4",
		"windows",
	).SetPolicy(baseTCPConnectPolicy)

	TCPAccept6 = program.Builder(
		"tcp_connect.sys",
		"cgroup/recv_accept6",
		"tcp_accept6",
		"tcp::accept6",
		"windows",
	).SetPolicy(baseTCPConnectPolicy)

	SockOps = program.Builder(
		"tcp_connect.sys",
		"sockops",
		"sockops_monitor",
		"tcp::sockops_monitor",
		"windows",
	).SetPolicy(baseTCPConnectPolicy)

	baseTCPPrograms = []*program.Program{
		TCPConnect4,
		TCPConnect6,
		TCPAccept4,
		TCPAccept6,
		SockOps,
	}
)

func ConfigureSensor() error {
	return nil
}

func LoadWinTCPSensor(ctx context.Context) error {
	if !enterpriseOption.Config.EnableTCP {
		return nil
	}
	mgr := observer.GetSensorManager()
	initialTCPSensor := &sensors.Sensor{
		Name:  baseTCPConnectPolicy,
		Progs: baseTCPPrograms,
		Maps:  []*program.Map{},
	}
	if err := mgr.AddSensor(ctx, initialTCPSensor.Name, initialTCPSensor); err != nil {
		return err
	}
	return mgr.EnableSensor(ctx, initialTCPSensor.Name)
}

func handleTcpClose(r *bytes.Reader) ([]observer.Event, error) {
	m := networkapi.MsgIPWithStatsEvent{}
	var err error
	err = binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		return nil, err
	}
	m.Common.Ktime = common.KTimeToWindowsEpoch(m.Common.Ktime)
	tcp := ip.MsgToIPWithStatsUnix(&m)
	events := []observer.Event{tcp}
	return events, err
}

func handleTcp(r *bytes.Reader) ([]observer.Event, error) {
	m := networkapi.MsgIPEvent{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		return nil, err
	}
	m.Common.Ktime = common.KTimeToWindowsEpoch(m.Common.Ktime)
	tcp := ip.MsgToIPUnix(&m)

	return []observer.Event{tcp}, nil
}

func init() {
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_TCPCONNECTRET, handleTcp)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_ACCEPT, handleTcp)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_TCPCLOSE, handleTcpClose)
}
