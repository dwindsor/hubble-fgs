//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package layer3

import (
	"context"

	"github.com/cilium/tetragon/pkg/constants"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/internal/tcp"
)

func ProgsAndMaps(tcpTimestampEnable, cgroup, udpTimestampEnable bool) ([]*program.Program, []*program.Map) {
	return nil, nil
}

func EnableLayer3Progs() error {
	return constants.ErrWindowsNotSupported
}

func RunLayer3Progs(ctx context.Context) error {
	return constants.ErrWindowsNotSupported
}

func StartLayer3Progs(ctx context.Context) error {
	return constants.ErrWindowsNotSupported
}

func LoadWinTCPSensor(ctx context.Context) error {
	return tcp.LoadWinTCPSensor(ctx)
}

func HTTPContext() *program.Map {
	return nil
}

func SocketMap() *program.Map {
	return nil
}

func SocketStats() *program.Map {
	return nil
}

func TcpSocketMap() *program.Map {
	return nil
}

func TcpSocketStats() *program.Map {
	return nil
}

func TLSContext() *program.Map {
	return nil
}

func TLSMapStats() *program.Map {
	return nil
}

func TLSBottles() *program.Map {
	return nil
}

func TLSBottleStats() *program.Map {
	return nil
}
