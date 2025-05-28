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

	TCPConnect = program.Builder(
		"tcp_connect.sys",
		"cgroup/connect4",
		"tcp_connect4",
		"tcp::connect",
		"windows",
	).SetPolicy(baseTCPConnectPolicy)

	baseTCPPrograms = []*program.Program{
		TCPConnect,
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
}
