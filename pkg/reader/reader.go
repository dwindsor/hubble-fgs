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

	"bytes"
	"encoding/binary"
	"encoding/gob"
	"golang.org/x/sys/unix"
	"net"
	"strings"
	"syscall"
	"time"

	"go.uber.org/zap"
)

func GetIP(i uint32, op uint8) net.IP {
	if op == api.MSG_OP_IPV4_BIND {
		return net.IPv4zero
	}
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, i)
	return ip
}

func SwapByte(b uint16) uint16 {
	return (b << 8) | (b >> 8)
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
	if (flags & api.EventNoCWDSupport) != 0 {
		s = append(s, "nocwd")
	}
	if (flags & api.EventRootCWD) != 0 {
		s = append(s, "rootcwd")
	}
	if (flags & api.EventErrorCWD) != 0 {
		s = append(s, "errorCWD")
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

func argsDecoderTrim(r rune) bool {
	if r == 0x00 {
		return true
	}
	return false
}

func ArgsDecoder(s string, flags uint32) (string, string) {
	var b []byte
	var cwd string
	args := ""

	b = append(b, 0x00)
	argTokens := bytes.Split(bytes.TrimRightFunc([]byte(s), argsDecoderTrim), b)

	if (flags & api.EventNoCWDSupport) != 0 {
		cwd = ""
	} else if (flags & api.EventErrorCWD) != 0 {
		cwd = ""
	} else if (flags & api.EventRootCWD) != 0 {
		cwd = "/"
	} else {
		dirs := strings.Split(string(argTokens[len(argTokens)-1]), "/")
		for i := len(dirs)/2 - 1; i >= 0; i-- {
			opp := len(dirs) - 1 - i
			dirs[i], dirs[opp] = dirs[opp], dirs[i]
		}
		cwd = strings.Join(dirs, "/")
		cwd = "/" + cwd
	}

	if len(argTokens) > 1 {
		for i, a := range argTokens {
			if i == len(argTokens)-1 {
				continue
			}
			if strings.Contains(string(a), " ") {
				args = args + " \"" + string(a) + "\""
			} else {
				if args == "" {
					args = string(a)
				} else {
					args = args + " " + string(a)
				}
			}
		}
	}
	return args, cwd
}

func GetSport(sport uint16) uint16 {
	return sport
}
func GetDport(dport uint16, op uint8) uint16 {
	if op == api.MSG_OP_IPV4_BIND || op == api.MSG_OP_IPV4_LISTEN {
		return 0
	}
	return SwapByte(dport)
}

func ObserverIPV4TCPConnectPrinter(msg *api.MsgIPv4TcpConnectUnix, log *zap.Logger) {
	e := syscall.Errno(uintptr(-msg.Return))
	/* In the event of an error time is {0} so will be obvious at printer time
	 * and its not clear what to do with this error so ignore it for now.
	 */
	eventTime, _ := DecodeKtime(int64(msg.Common.Ktime))
	parentTime, _ := DecodeKtime(int64(msg.Pid.Parent.Ktime))
	childTime, _ := DecodeKtime(int64(msg.Pid.Curr.Ktime))

	parentArgs, parentCWD := ArgsDecoder(msg.Pid.Parent.Args, msg.Pid.Parent.Flags)
	childArgs, childCWD := ArgsDecoder(msg.Pid.Curr.Args, msg.Pid.Curr.Flags)

	op := msg.Common.Op

	log.Debug("KprobeEvent",
		zap.String("op", api.OpCode(op).String()),
		zap.Uint64("connect-ktime", msg.Common.Ktime),
		zap.Time("connect-walltime", eventTime),
		zap.Uint32("parent-size", msg.Pid.Parent.Size),
		zap.Uint32("parent-pid", msg.Pid.Parent.PID),
		zap.Uint32("parent-auid", msg.Pid.Parent.AUID),
		zap.Uint32("parent-uid", msg.Pid.Parent.UID),
		zap.String("parent-flags", DecodeCommonFlags(msg.Pid.Parent.Flags)),
		zap.Time("parent-walltime", parentTime),
		zap.String("parent-prog", msg.Pid.Parent.Filename),
		zap.String("parent-cwd", parentCWD),
		zap.String("parent-args", parentArgs),
		zap.Uint32("size", msg.Pid.Curr.Size),
		zap.Uint32("pid", msg.Pid.Curr.PID),
		zap.Uint32("auid", msg.Pid.Curr.AUID),
		zap.Uint32("uid", msg.Pid.Curr.UID),
		zap.String("flags", DecodeCommonFlags(msg.Pid.Curr.Flags)),
		zap.Time("walltime", childTime),
		zap.String("prog", msg.Pid.Curr.Filename),
		zap.String("cwd", childCWD),
		zap.String("args", childArgs),
		zap.Uint8("proto", msg.Tuple.Proto),
		zap.String("saddr", GetIP(msg.Tuple.SAddr, op).String()),
		zap.Uint16("sport", GetSport(msg.Tuple.SPort)),
		zap.String("daddr", GetIP(msg.Tuple.DAddr, op).String()),
		zap.Uint16("dport", GetDport(msg.Tuple.DPort, op)),
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
