// Copyright 2019 Authors of Hubble
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package reader

import (
	"github.com/covalentio/hubble-fgs/pkg/api"
	"github.com/covalentio/hubble-fgs/pkg/defaults"

	"encoding/binary"
	"encoding/gob"
	"net"

	"go.uber.org/zap"
)

func GetIP(i uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, i)
	return ip
}

func SwapByte(b uint16) uint16 {
	return (b << 8) | (b >> 8)
}

func ObserverIPV4TCPConnectPrinter(msg *api.MsgIPv4TcpConnectUnix, log *zap.Logger) {
	log.Debug("KprobeEvent",
		zap.Uint32("parent-pid", msg.Pid.Parent.PID),
		zap.Uint32("parent-uid", msg.Pid.Parent.UID),
		zap.String("parent-prog", msg.Pid.Parent.Filename),
		zap.Strings("parent-args", msg.Pid.Parent.Args),
		zap.Uint32("pid", msg.Pid.Curr.PID),
		zap.Uint32("uid", msg.Pid.Curr.UID),
		zap.String("prog", msg.Pid.Curr.Filename),
		zap.Strings("args", msg.Pid.Curr.Args),
		zap.Uint8("proto", msg.Tuple.Proto),
		zap.String("saddr", GetIP(msg.Tuple.SAddr).String()),
		zap.Uint16("sport", msg.Tuple.SPort),
		zap.String("daddr", GetIP(msg.Tuple.DAddr).String()),
		zap.Uint16("dport", SwapByte(msg.Tuple.DPort)),
		zap.String("DockerID", msg.Kube.Docker),
	)
}

func ObserverReceiver(log *zap.Logger) error {
	conn, err := net.Dial("unix", defaults.DefaultUnixSock)

	if err != nil {
		return err
	}

	for {
		dec := gob.NewDecoder(conn)
		var IPv4TCPConnectMsg api.MsgIPv4TcpConnectUnix

		err = dec.Decode(&IPv4TCPConnectMsg)
		if err != nil {
			return err
		}

		ObserverIPV4TCPConnectPrinter(&IPv4TCPConnectMsg, log)
	}
}
