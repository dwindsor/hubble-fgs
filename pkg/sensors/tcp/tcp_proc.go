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

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/proc"
	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/grpc/layer3"
	"github.com/isovalent/hubble-fgs/pkg/sensors/ip"
	"github.com/sirupsen/logrus"
)

const (
	IPPROTO_TCP           = 6
	TCP_PROC_STATE_LISTEN = 10
)

var (
	// Mutex to prevent concurrent loading
	loading sync.Mutex

	_pushEvents = false
)

func FdCallback(socket *ip.FdLookupValue, pid uint32) {
	saddr := networkapi.GetIP(socket.Saddr, 0, socket.IPv6 != 0)
	daddr := networkapi.GetIP(socket.Daddr, 0, socket.IPv6 != 0)
	logger.GetLogger().WithFields(logrus.Fields{"Pid": pid, "Saddr": saddr, "Daddr": daddr, "Sport": socket.Sport, "Dport": socket.Dport, "Protocol": socket.Protocol, "State": socket.State, "Cookie": socket.Sockaddr}).Debug("Discovered TCP Socket")

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
	tcp.Msg = &networkapi.MsgIPEvent{}

	tcp.Msg.ProcessKey.Pid = pid
	tcp.Msg.ProcessKey.Ktime = ktime
	tcp.Msg.Common.Ktime = ktime

	tcp.Msg.Tuple.IPv6 = socket.IPv6
	tcp.Msg.Tuple.SAddr[0] = socket.Saddr[0]
	tcp.Msg.Tuple.SAddr[1] = socket.Saddr[1]
	tcp.Msg.Tuple.DAddr[0] = socket.Daddr[0]
	tcp.Msg.Tuple.DAddr[1] = socket.Daddr[1]
	tcp.Msg.Tuple.DPort = socket.Dport
	tcp.Msg.Tuple.SPort = socket.Sport
	tcp.Msg.Tuple.Proto = 2
	tcp.Msg.SockCookie = socket.Sockaddr

	if socket.State == TCP_PROC_STATE_LISTEN {
		tcp.Msg.Common.Op = ops.MsgOpListen
	} else {
		tcp.Msg.Common.Op = ops.MsgOpTCPConnectReturn
	}

	if _pushEvents {
		observer.AllListeners(&tcp)
	}
}

func getRunningSockets(_, pushEvents bool) {
	/* Lock is required to prevent concurrent access to object vars,
	 * just in case this gets called twice at once.
	 */
	loading.Lock()
	defer loading.Unlock()

	_pushEvents = pushEvents
	ip.LoadSockets(FdCallback, IPPROTO_TCP)
}
