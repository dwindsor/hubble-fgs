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
	"syscall"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/proc"
	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	grpc "github.com/isovalent/hubble-fgs/pkg/grpc/layer3"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/internal/ip"
	"github.com/sirupsen/logrus"
)

const (
	TCP_PROC_STATE_LISTEN     = 10
	TCP_LEARN_LISTEN_SOCKETS  = 1
	TCP_LEARN_CONNECT_SOCKETS = 2
)

var (
	// Mutex to prevent concurrent loading
	loading sync.Mutex

	_pushEvents = false
)

func fdCallback(socket *networkapi.FdLookupValue, pid uint32) {
	saddr := networkapi.GetIP(socket.Tuple.SAddr, 0, socket.Tuple.IPv6 != 0)
	daddr := networkapi.GetIP(socket.Tuple.DAddr, 0, socket.Tuple.IPv6 != 0)
	logger.GetLogger().WithFields(logrus.Fields{"Pid": pid, "Saddr": saddr, "Daddr": daddr, "Sport": socket.Tuple.SPort, "Dport": socket.Tuple.DPort, "Protocol": socket.Protocol, "State": socket.State, "Cookie": socket.Sockaddr, "SockVersion": socket.SockVersion}).Debug("Discovered TCP Socket")

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

	tcp := grpc.MsgIPEventUnix{}
	tcp.Msg = &networkapi.MsgIPEvent{}

	tcp.Msg.ProcessKey.Pid = pid
	tcp.Msg.ProcessKey.Ktime = ktime
	tcp.Msg.Common.Ktime = ktime

	tcp.Msg.Tuple.IPv6 = socket.Tuple.IPv6
	tcp.Msg.Tuple.SAddr[0] = socket.Tuple.SAddr[0]
	tcp.Msg.Tuple.SAddr[1] = socket.Tuple.SAddr[1]
	tcp.Msg.Tuple.DAddr[0] = socket.Tuple.DAddr[0]
	tcp.Msg.Tuple.DAddr[1] = socket.Tuple.DAddr[1]
	tcp.Msg.Tuple.DPort = socket.Tuple.DPort
	tcp.Msg.Tuple.SPort = socket.Tuple.SPort
	tcp.Msg.Tuple.Proto = syscall.IPPROTO_TCP
	tcp.Msg.SockCookie = socket.Sockaddr
	tcp.Msg.Version = socket.SockVersion

	if socket.State == TCP_PROC_STATE_LISTEN {
		tcp.Msg.Common.Op = ops.MSG_OP_LISTEN
	} else {
		tcp.Msg.Common.Op = ops.MSG_OP_TCPCONNECTRET
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
	ip.LoadSockets(fdCallback, syscall.IPPROTO_TCP, TCP_LEARN_LISTEN_SOCKETS)
	ip.LoadSockets(fdCallback, syscall.IPPROTO_TCP, TCP_LEARN_CONNECT_SOCKETS)
}
