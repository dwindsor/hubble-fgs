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
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/covalentio/hubble-fgs/pkg/api"
	"github.com/covalentio/hubble-fgs/pkg/defaults"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func GetIP(i uint32, op uint8) net.IP {
	if op == api.MSG_OP_IPV4_BIND {
		return net.IPv4zero
	}
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, i)
	return ip
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
	if (flags & api.EventClone) != 0 {
		s = append(s, "clone")
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

func SwapPath(path string) string {
	dirs := strings.Split(path, "/")
	for i := len(dirs)/2 - 1; i >= 0; i-- {
		opp := len(dirs) - 1 - i
		dirs[i], dirs[opp] = dirs[opp], dirs[i]
	}
	return strings.Join(dirs, "/")
}

func ArgsDecoder(s string, flags uint32) (string, string) {
	var b []byte
	var cwd string
	var hasCWD int
	args := ""

	b = append(b, 0x00)
	argTokens := bytes.Split(bytes.TrimRightFunc([]byte(s), argsDecoderTrim), b)
	flagsOR := ((flags & api.EventNoCWDSupport) |
		(flags & api.EventErrorCWD) |
		(flags & api.EventRootCWD))
	if flagsOR == 0 {
		hasCWD = 1
	} else {
		hasCWD = 0
	}

	if (flags & api.EventNoCWDSupport) != 0 {
		cwd = ""
	} else if (flags & api.EventErrorCWD) != 0 {
		cwd = ""
	} else if (flags & api.EventRootCWD) != 0 {
		cwd = "/"
	} else {
		cwd = "/" + SwapPath(string(argTokens[len(argTokens)-1]))
	}

	if len(argTokens) > hasCWD {
		for i, a := range argTokens {
			if i == len(argTokens)-hasCWD {
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
	return api.SwapByte(dport)
}

func ObserverIPV4TCPConnectPrinter(msg *api.MsgIPv4TcpConnectUnix, log logrus.FieldLogger) {
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

	log.WithFields(logrus.Fields{
		"op":               api.OpCode(op).String(),
		"connect-ktime":    msg.Common.Ktime,
		"connect-walltime": eventTime,
		"parent-size":      msg.Pid.Parent.Size,
		"parent-pid":       msg.Pid.Parent.PID,
		"parent-nspid":     msg.Pid.Parent.NSPID,
		"parent-auid":      msg.Pid.Parent.AUID,
		"parent-uid":       msg.Pid.Parent.UID,
		"parent-flags":     DecodeCommonFlags(msg.Pid.Parent.Flags),
		"parent-ktime":     msg.Pid.Parent.Ktime,
		"parent-walltime":  parentTime,
		"parent-prog":      msg.Pid.Parent.Filename,
		"parent-cwd":       parentCWD,
		"parent-args":      parentArgs,
		"size":             msg.Pid.Curr.Size,
		"pid":              msg.Pid.Curr.PID,
		"nspid":            msg.Pid.Curr.NSPID,
		"auid":             msg.Pid.Curr.AUID,
		"uid":              msg.Pid.Curr.UID,
		"flags":            DecodeCommonFlags(msg.Pid.Curr.Flags),
		"ktime":            msg.Pid.Curr.Ktime,
		"walltime":         childTime,
		"prog":             msg.Pid.Curr.Filename,
		"cwd":              childCWD,
		"args":             childArgs,
		"proto":            msg.Tuple.Proto,
		"saddr":            GetIP(msg.Tuple.SAddr, op).String(),
		"sport":            GetSport(msg.Tuple.SPort),
		"daddr":            GetIP(msg.Tuple.DAddr, op).String(),
		"odaddr":           GetIP(msg.Tuple.GetPostDAddr(), op).String(),
		"dport":            GetDport(msg.Tuple.DPort, op),
		"odport":           GetDport(msg.Tuple.GetPostDPort(), op),
		"container-id":     msg.Kube.Docker,
		"return":           unix.ErrnoName(e),
	}).Debug()
}

func ObserverReceiver(log logrus.FieldLogger) error {
	conn, err := net.Dial("unix", defaults.GetSocketPath())
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
