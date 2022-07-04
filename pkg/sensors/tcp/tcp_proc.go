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
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/namespace"
	"github.com/cilium/tetragon/pkg/reader/proc"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/grpc/layer3"
	"github.com/isovalent/hubble-fgs/pkg/reader/network"
	"github.com/isovalent/hubble-fgs/pkg/sensors/ip"
	"github.com/sirupsen/logrus"
)

const (
	IPPROTO_TCP = 6
)

var (
	// Mutex to prevent concurrent loading
	loading sync.Mutex

	_writeMaps  = false
	_pushEvents = false
	m           *bpf.Map
)

func FdCallback(socket *ip.FdLookupValue, pid uint32) {
	saddr := network.GetIP(socket.Saddr, 0, socket.IPv6 != 0)
	daddr := network.GetIP(socket.Daddr, 0, socket.IPv6 != 0)
	logger.GetLogger().WithFields(logrus.Fields{"Pid": pid, "Saddr": saddr, "Daddr": daddr, "Sport": socket.Sport, "Dport": socket.Dport, "Protocol": socket.Protocol, "State": socket.State}).Debug("Discovered TCP Socket")

	if socket.State == 0 {
		return
	}

	pathName := filepath.Join(option.Config.ProcFS, fmt.Sprintf("%d", pid))
	stats, err := proc.GetProcStatStrings(pathName)
	if err != nil {
		return
	}
	ktime, err := proc.GetStatsKtime(stats)
	if err != nil {
		return
	}

	tcp := layer3.MsgIPEventUnix{}

	tcp.ProcessKey.Pid = pid
	tcp.ProcessKey.Ktime = ktime
	tcp.Common.Ktime = ktime

	tcp.Tuple.IPv6 = socket.IPv6
	tcp.Tuple.SAddr[0] = socket.Saddr[0]
	tcp.Tuple.SAddr[1] = socket.Saddr[1]
	tcp.Tuple.DAddr[0] = socket.Daddr[0]
	tcp.Tuple.DAddr[1] = socket.Daddr[1]
	tcp.Tuple.DPort = network.SwapByte(socket.Dport)
	tcp.Tuple.SPort = socket.Sport
	tcp.Tuple.Proto = 2

	if socket.State == TCP_PROC_STATE_LISTEN {
		tcp.Common.Op = ops.MsgOpListen
	} else {
		tcp.Common.Op = ops.MsgOpTCPConnectReturn
	}

	if _pushEvents {
		observer.AllListeners(&tcp)
	}
	if _writeMaps {
		netns := uint64(namespace.GetPidNsInode(pid, "net"))
		writeSockMap(&tcp, m, netns)
	}
}

func getRunningSockets(writeMaps, pushEvents bool) {
	/* Lock is required to prevent concurrent access to object vars,
	 * just in case this gets called twice at once.
	 */
	loading.Lock()
	defer loading.Unlock()

	_writeMaps = writeMaps
	_pushEvents = pushEvents

	if writeMaps {
		var err error
		mapDir := bpf.MapPrefixPath()

		m, err = bpf.OpenMap(filepath.Join(mapDir, SocketMap.Name))
		for i := 0; err != nil; i++ {
			m, err = bpf.OpenMap(filepath.Join(mapDir, SocketMap.Name))
			if err != nil {
				time.Sleep(mapRetryDelay * time.Second)
			}
			if i > maxMapRetries {
				panic(err)
			}
		}
		defer m.Close()
	}

	ip.LoadSockets(FdCallback, IPPROTO_TCP)
}
