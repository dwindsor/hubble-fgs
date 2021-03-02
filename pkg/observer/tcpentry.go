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

	"github.com/covalentio/hubble-fgs/pkg/api"
	"github.com/covalentio/hubble-fgs/pkg/bpf"
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
	Pid   uint32
	Pad   uint32
	Ktime uint64
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

func (k *ObserverKprobe) getPidNetNsInode(pid uint32) uint64 {
	pidStr := strconv.Itoa(int(pid))
	netns := filepath.Join(ProcFS, pidStr, "ns", "net")
	netStr, err := os.Readlink(netns)
	if err != nil {
		k.log.WithError(err).Warnf("NetNSInode read (%d) failed", pid)
		return 0
	}
	fields := strings.Split(netStr, ":")
	if len(fields) < 2 {
		k.log.WithError(err).Warnf("NetNSInode format invalid %s", netStr)
		return 0
	}
	inode := fields[1]
	inode = strings.TrimRight(inode, "]")
	inode = strings.TrimLeft(inode, "[")
	inodeEntry, err := strconv.ParseUint(inode, 10, 32)
	return inodeEntry
}

func (k *ObserverKprobe) pushTCPEvents(msg *api.MsgExecveEventUnix, tcpEntries map[uint32]procTCPEntry, writeMaps, pushEvents bool) {
	var m *bpf.Map

	pid := msg.Process.PID
	tcp := api.MsgIPv4TcpEventUnix{}

	tcp.ProcessKey.Pid = pid
	tcp.ProcessKey.Ktime = msg.Process.Ktime
	tcp.Common.Ktime = msg.Process.Ktime

	netns := k.getPidNetNsInode(pid)

	fdDir := fmt.Sprintf("%s/%d/fd", ProcFS, pid)
	procFD, err := ioutil.ReadDir(fdDir)
	if err != nil {
		k.log.WithError(err).Warnf("ReadDir %d/fd/ failed", pid)
	}

	if writeMaps {
		var err error

		m, err = bpf.OpenMap(filepath.Join(k.mapDir, ObserverSocketMap.mapName))
		for i := 0; err != nil; i++ {
			m, err = bpf.OpenMap(filepath.Join(k.mapDir, ObserverSocketMap.mapName))
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
				entry, ok := tcpEntries[uint32(inodeEntry)]
				if !ok {
					continue
				}
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

				if pushEvents {
					k.observerListenersTcp(&tcp)
				}
				if writeMaps {
					k.writeSockMap(&tcp, m, netns)
				}
			}
		}
	}
}

func (k *ObserverKprobe) writeSockMap(tcp *api.MsgIPv4TcpEventUnix, m *bpf.Map, uid uint64) {
	key := &SocketMapKey{
		Saddr:     tcp.Tuple.SAddr,
		Daddr:     tcp.Tuple.DAddr,
		Dport:     tcp.Tuple.DPort,
		Sport:     tcp.Tuple.SPort,
		Uid:       uid,
		Remaining: 0,
	}

	val := &SocketMapValue{
		Pid:   tcp.ProcessKey.Pid,
		Pad:   0,
		Ktime: tcp.ProcessKey.Ktime,
	}
	m.Update(key, val)
}
