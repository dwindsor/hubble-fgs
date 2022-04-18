//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package observer

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/bpf"
	"github.com/isovalent/hubble-fgs/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/reader"
	"github.com/isovalent/hubble-fgs/pkg/sensors"
)

type SocketMapKey struct {
	Saddr     uint32
	Daddr     uint32
	Dport     uint16
	Sport     uint16
	Remaining uint32
	Uid       uint64
}

type SocketMapValue struct {
	Pid     uint32 `align:"key"`
	Pad1    uint32
	Ktime   uint64
	ZeroWin uint32 `align:"zero_window"`
	SFlags  uint32 `align:"socket_flags"`
}

func bpfIpToString(ip uint32) string {
	scratch := make(net.IP, 4)

	scratch[0] = byte(ip)
	scratch[1] = byte(ip >> 8)
	scratch[2] = byte(ip >> 16)
	scratch[3] = byte(ip >> 24)

	return scratch.String()
}

func (k *SocketMapKey) String() string {
	return fmt.Sprintf("%s:%d %s:%d meta(uid %d, remaining %d)",
		bpfIpToString(k.Saddr), k.Sport,
		bpfIpToString(k.Daddr), k.Dport,
		k.Uid, k.Remaining)
}
func (k *SocketMapKey) NewValue() bpf.MapValue     { return &SocketMapValue{} }
func (k *SocketMapKey) GetKeyPtr() unsafe.Pointer  { return unsafe.Pointer(k) }
func (k *SocketMapKey) DeepCopyMapKey() bpf.MapKey { return &SocketMapKey{} }

func (v *SocketMapValue) String() string {
	return fmt.Sprintf("%d %d", v.Pid, v.Ktime)
}
func (v *SocketMapValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }
func (v *SocketMapValue) DeepCopyMapValue() bpf.MapValue {
	return &SocketMapValue{}
}

type procTCPEntry struct {
	id         int
	localIP    uint32
	localPort  uint16
	remoteIP   uint32
	remotePort uint16
	state      uint32
	inode      uint32
}

func pushTCPEvents(pid uint32, ktime uint64, tcpEntries map[uint32]procTCPEntry, writeMaps, pushEvents bool) {
	var m *bpf.Map

	tcp := api.MsgIPv4EventUnix{}

	tcp.ProcessKey.Pid = pid
	tcp.ProcessKey.Ktime = ktime
	tcp.Common.Ktime = ktime

	netns := uint64(reader.GetPidNsInode(pid, "net"))

	fdDir := fmt.Sprintf("%s/%d/fd", option.Config.ProcFS, pid)
	procFD, err := ioutil.ReadDir(fdDir)
	if err != nil {
		logger.GetLogger().WithError(err).Warnf("ReadDir %d/fd/ failed", pid)
	}

	if writeMaps {
		var err error
		mapDir := reader.GetObserverDir()

		m, err = bpf.OpenMap(filepath.Join(mapDir, sensors.SocketMap.Name))
		for i := 0; err != nil; i++ {
			m, err = bpf.OpenMap(filepath.Join(mapDir, sensors.SocketMap.Name))
			if err != nil {
				time.Sleep(mapRetryDelay * time.Second)
			}
			if i > maxMapRetries {
				panic(err)
			}
		}
		defer m.Close()
	}

	for _, d := range procFD {
		socket, err := os.Readlink(filepath.Join(fdDir, d.Name()))
		if err != nil && option.Config.Verbosity > 0 {
			logger.GetLogger().WithError(err).Warnf("Readlink error %s", d.Name())
		}
		if strings.Contains(socket, "socket") == true {
			fields := strings.Split(socket, ":")
			if len(fields) < 2 {
				continue
			}
			inode := fields[1]
			inode = strings.TrimRight(inode, "]")
			inode = strings.TrimLeft(inode, "[")
			inodeEntry, err := strconv.ParseUint(inode, 10, 32)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("tcpEntry inode not parsable: %s", inode)
			} else {
				entry, ok := tcpEntries[uint32(inodeEntry)]
				if !ok {
					continue
				}
				tcp.Tuple.SAddr = entry.localIP
				tcp.Tuple.DAddr = entry.remoteIP
				tcp.Tuple.DPort = api.SwapByte(entry.remotePort)
				tcp.Tuple.SPort = entry.localPort
				tcp.Tuple.Proto = 2

				if entry.state == 0 {
					continue
				}

				if entry.state == TCP_PROC_STATE_LISTEN {
					tcp.Common.Op = api.MsgOpIPv4Listen
				} else {
					tcp.Common.Op = api.MsgOpIPv4TCPConnectReturn
				}

				if pushEvents {
					AllListeners(&tcp)
				}
				if writeMaps {
					writeSockMap(&tcp, m, netns)
				}
			}
		}
	}
}

func writeSockMap(tcp *api.MsgIPv4EventUnix, m *bpf.Map, uid uint64) {
	key := &SocketMapKey{
		Saddr:     tcp.Tuple.SAddr,
		Daddr:     tcp.Tuple.DAddr,
		Dport:     tcp.Tuple.DPort,
		Sport:     tcp.Tuple.SPort,
		Remaining: 0,
		Uid:       uid,
	}

	val := &SocketMapValue{
		Pid:     tcp.ProcessKey.Pid,
		Pad1:    0,
		Ktime:   tcp.ProcessKey.Ktime,
		ZeroWin: 0,
		SFlags:  0,
	}
	m.Update(key, val)
}
