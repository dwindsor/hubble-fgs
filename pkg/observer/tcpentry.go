package observer

import (
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"github.com/covalentio/hubble-fgs/pkg/api"
)

type procTCPEntry struct {
	id                   int
	localIP              uint32
	localPort            uint16
	remoteIP             uint32
	remotePort           uint16
	state                uint32
	txq                  int
	rxq                  int
	timerActive          int
	jiffiesExpire        uint64
	jiffiesRTO           uint64
	uid                  uint32
	unansweredProbes     uint32
	inode                uint32
	socketRefCount       uint32
	locationSocketMemory uint64
	retransTimeout       uint64
	predictedTick        uint64
	congestionWindow     uint64
	slowstartThresh      uint64
}

func (k *ObserverKprobe) pushTCPEvents(msg *api.MsgExecveEventUnix, tcpEntries map[uint32]procTCPEntry) {
	pid := msg.Process.PID
	tcp := api.MsgIPv4TcpEventUnix{}

	tcp.ProcessKey.Pid = pid
	tcp.ProcessKey.Ktime = msg.Process.Ktime
	tcp.Common.Ktime = msg.Process.Ktime

	fdDir := fmt.Sprintf("%s/%d/fd", ProcFS, pid)
	procFD, err := ioutil.ReadDir(fdDir)
	if err != nil {
		k.log.WithError(err).Warnf("ReadDir %d/fd/ failed", pid)
	}
	for _, d := range procFD {
		socket, err := os.Readlink(fdDir + "/" + d.Name())
		if err != nil && Verbosity > 0 {
			k.log.WithError(err).Warnf("Readlink error %s", d.Name())
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
				k.log.WithError(err).Warnf("tcpEntry inode not parsable: %s", inode)
			} else {
				entry := tcpEntries[uint32(inodeEntry)]
				tcp.Tuple.SAddr = entry.localIP
				tcp.Tuple.DAddr = entry.remoteIP
				tcp.Tuple.DPort = entry.remotePort
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

				k.observerListenersTcp(&tcp)
			}
		}
	}
}
