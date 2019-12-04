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
	"golang.org/x/sys/unix"
	"net"
	"strings"
	"syscall"
	"time"

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

func ReplaceNewLines(s string, c rune) string {
	r := []rune(s)

	for i, _r := range r {
		if _r == 0x0000 {
			r[i] = c
		}
	}
	return strings.TrimSpace(string(r))
}

func DecodeCommonFlags(flags uint32) string {
	var s []string
	if (flags & api.EventExecve) != 0 {
		s = append(s, "execve")
	}
	if (flags & api.EventExecveAt) != 0 {
		s = append(s, "execveat")
	}
	if (flags & api.EventProcFS) != 0 {
		s = append(s, "procFS")
	}
	if (flags & api.EventTruncFilename) != 0 {
		s = append(s, "truncFilename")
	}
	if (flags & api.EventTruncArgs) != 0 {
		s = append(s, "truncArgs")
	}
	if (flags & api.EventTaskWalk) != 0 {
		s = append(s, "taskWalk")
	}
	if (flags & api.EventMiss) != 0 {
		s = append(s, "miss")
	}
	if (flags & api.EventNeedsAUID) != 0 {
		s = append(s, "auid")
	}
	if (flags & api.EventErrorFilename) != 0 {
		s = append(s, "errorFilename")
	}
	if (flags & api.EventErrorArgs) != 0 {
		s = append(s, "errorArgs")
	}
	return strings.Join(s, " ")
}

func DecodeKtime(ktime int64) (time.Time, error) {
	clk := int32(unix.CLOCK_MONOTONIC)
	currentTime := unix.Timespec{}
	if err := unix.ClockGettime(clk, &currentTime); err != nil {
		return time.Time{}, err
	}
	diff := ktime - currentTime.Nano()
	return time.Now().Add(time.Duration(diff)), nil
}

func ObserverIPV4TCPConnectPrinter(msg *api.MsgIPv4TcpConnectUnix, log *zap.Logger) {
	e := syscall.Errno(uintptr(-msg.Return))
	/* In the event of an error time is {0} so will be obvious at printer time
	 * and its not clear what to do with this error so ignore it for now.
	 */
	eventTime, _ := DecodeKtime(int64(msg.Common.Ktime))
	parentTime, _ := DecodeKtime(int64(msg.Pid.Parent.Ktime))
	childTime, _ := DecodeKtime(int64(msg.Pid.Curr.Ktime))

	log.Debug("KprobeEvent",
		zap.Uint8("op", msg.Common.Op),
		zap.Uint64("connect-ktime", msg.Common.Ktime),
		zap.Time("connect-walltime", eventTime),
		zap.Uint32("parent-size", msg.Pid.Parent.Size),
		zap.Uint32("parent-pid", msg.Pid.Parent.PID),
		zap.Uint32("parent-auid", msg.Pid.Parent.AUID),
		zap.Uint32("parent-uid", msg.Pid.Parent.UID),
		zap.String("parent-flags", DecodeCommonFlags(msg.Pid.Parent.Flags)),
		zap.Time("parent-walltime", parentTime),
		zap.String("parent-prog", msg.Pid.Parent.Filename),
		zap.String("parent-args", ReplaceNewLines(msg.Pid.Parent.Args, rune(0x0020))),
		zap.Uint32("size", msg.Pid.Curr.Size),
		zap.Uint32("pid", msg.Pid.Curr.PID),
		zap.Uint32("auid", msg.Pid.Curr.AUID),
		zap.Uint32("uid", msg.Pid.Curr.UID),
		zap.String("flags", DecodeCommonFlags(msg.Pid.Curr.Flags)),
		zap.Time("walltime", childTime),
		zap.String("prog", msg.Pid.Curr.Filename),
		zap.String("args", ReplaceNewLines(msg.Pid.Curr.Args, rune(0x0020))),
		zap.Uint8("proto", msg.Tuple.Proto),
		zap.String("saddr", GetIP(msg.Tuple.SAddr).String()),
		zap.Uint16("sport", msg.Tuple.SPort),
		zap.String("daddr", GetIP(msg.Tuple.DAddr).String()),
		zap.Uint16("dport", SwapByte(msg.Tuple.DPort)),
		zap.String("ContainerID", msg.Kube.Docker),
		zap.String("return", unix.ErrnoName(e)),
	)
}

func ObserverReceiver(log *zap.Logger) error {
	conn, err := net.Dial("unix", defaults.DefaultUnixSock)
	if err != nil {
		return err
	}

	dec := gob.NewDecoder(conn)
	for {
		var IPv4TCPConnectMsg api.MsgIPv4TcpConnectUnix

		err = dec.Decode(&IPv4TCPConnectMsg)
		if err != nil {
			continue
		}

		ObserverIPV4TCPConnectPrinter(&IPv4TCPConnectMsg, log)
	}
}
