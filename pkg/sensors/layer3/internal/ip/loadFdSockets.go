//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package ip

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/cgroups"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/proc"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const (
	maxMapRetries         = 4
	mapRetryDelay         = 1
	FdLookupConfigMapName = "fd_lookup_config_map"
	SocketMapName         = "tg_socket_map"
	SocketMapStatsName    = "tg_socket_map_stats"
)

type FdCallback func(*networkapi.FdLookupValue, uint32)

var (
	// Mutex to prevent concurrent access
	access sync.Mutex

	// Socket lookup program
	// Ensure every program has a type defined by the layer3 sensor to force loading
	// through our own LoadProbe function. This is essential for socket discovery.
	FdLookupKprobe = program.Builder(
		"bpf_fd_lookup.o",
		"proc_task_name",
		"kprobe/proc_task_name",
		"kprobe_proc_task_name",
		"layer3_sensor",
	)

	FdLookupFentry = program.Builder(
		"bpf_fd_lookup_fentry.o",
		"fentry",
		"fentry/proc_task_name",
		"fentry_proc_task_name",
		"layer3_sensor",
	)

	FdLookupKprobe_5_15 = program.Builder(
		"bpf_fd_lookup_5_15.o",
		"proc_task_name",
		"kprobe/proc_task_name",
		"kprobe_proc_task_name",
		"layer3_sensor",
	)

	FdLookupFentry_5_15 = program.Builder(
		"bpf_fd_lookup_fentry_5_15.o",
		"fentry",
		"fentry/proc_task_name",
		"fentry_proc_task_name",
		"layer3_sensor",
	)

	// All the FdLookup sensor maps below are accessed from other sensors,
	// so they need to stay global as is expected by its users.

	// Socket lookup config map
	FdLookupConfigMapKprobe = program.MapBuilder(FdLookupConfigMapName, FdLookupKprobe)
	FdLookupConfigMapFentry = program.MapBuilder(FdLookupConfigMapName, FdLookupFentry)

	// Endpoint Models
	ProcessTreeIdMapKprobe = program.MapBuilder("tg_tree_id", FdLookupKprobe_5_15)
	ProcessTreeIdMapFentry = program.MapBuilder("tg_tree_id", FdLookupFentry_5_15)

	// Shared socket cookie infrastructure
	SocketCookieMapKprobe     = program.MapBuilder(SocketMapName, FdLookupKprobe, FdLookupKprobe_5_15)
	SocketCookieStatsKprobe   = program.MapBuilder(SocketMapStatsName, FdLookupKprobe, FdLookupKprobe_5_15)
	VerMapKprobe              = program.MapBuilder("tg_ver_map", FdLookupKprobe, FdLookupKprobe_5_15)
	SocketTupleMapKprobe      = program.MapBuilder("tg_socket_tuple_map", FdLookupKprobe, FdLookupKprobe_5_15)
	SocketTupleMapStatsKprobe = program.MapBuilder("tg_socket_tuple_map_stats", FdLookupKprobe, FdLookupKprobe_5_15)
	SocketTupleRevMapKprobe   = program.MapBuilder("tg_rev_tuple_map", FdLookupKprobe, FdLookupKprobe_5_15)
	SocketTupleHintMapKprobe  = program.MapBuilder("tg_socket_tuple_hint_map", FdLookupKprobe, FdLookupKprobe_5_15)
	TcpSocketMapKprobe        = program.MapBuilder("tg_tcpsocket_map", FdLookupKprobe, FdLookupKprobe_5_15)
	CfgMapKprobe              = program.MapBuilder("tg_cfg_map", FdLookupKprobe, FdLookupKprobe_5_15)
	SocketCookieMapFentry     = program.MapBuilder(SocketMapName, FdLookupFentry, FdLookupFentry_5_15)
	SocketCookieStatsFentry   = program.MapBuilder(SocketMapStatsName, FdLookupFentry, FdLookupFentry_5_15)
	VerMapFentry              = program.MapBuilder("tg_ver_map", FdLookupFentry, FdLookupFentry_5_15)
	SocketTupleMapFentry      = program.MapBuilder("tg_socket_tuple_map", FdLookupFentry, FdLookupFentry_5_15)
	SocketTupleMapStatsFentry = program.MapBuilder("tg_socket_tuple_map_stats", FdLookupFentry, FdLookupFentry_5_15)
	SocketTupleRevMapFentry   = program.MapBuilder("tg_rev_tuple_map", FdLookupFentry, FdLookupFentry_5_15)
	SocketTupleHintMapFentry  = program.MapBuilder("tg_socket_tuple_hint_map", FdLookupFentry, FdLookupFentry_5_15)
	TcpSocketMapFentry        = program.MapBuilder("tg_tcpsocket_map", FdLookupFentry, FdLookupFentry_5_15)
	CfgMapFentry              = program.MapBuilder("tg_cfg_map", FdLookupFentry, FdLookupFentry_5_15)
)

func Enable() ([]*program.Program, []*program.Map) {
	return getFdLookupPrograms(), getFdLookupMaps()
}

func getSocketFdsFromProcDir(dirname string) ([]uint32, error) {
	var socketFds []uint32
	fds, err := os.ReadDir(filepath.Join(dirname, "fd"))
	if err != nil {
		return nil, err
	}

	for _, fd := range fds {
		inodeStr, err := os.Readlink(filepath.Join(dirname, "fd", fd.Name()))
		if err != nil {
			continue
		}
		if !strings.HasPrefix(inodeStr, "socket:") && !strings.HasPrefix(inodeStr, "[0000]:") {
			continue
		}
		fdNum, err := strconv.ParseUint(fd.Name(), 10, 32)
		if err != nil {
			continue
		}
		socketFds = append(socketFds, uint32(fdNum))
	}

	return socketFds, nil
}

func getExistingSockets() (map[uint32][]uint32, error) {
	procSocketFds := make(map[uint32][]uint32)

	procFS, err := os.ReadDir(option.Config.ProcFS)
	if err != nil {
		logger.GetLogger().WithError(err).Errorf("Could not read directory %s", option.Config.ProcFS)
		return nil, err
	}

	for _, d := range procFS {
		if d.IsDir() == false {
			continue
		}

		pathName := filepath.Join(option.Config.ProcFS, d.Name())

		// Ignore any non-process directories
		cmdline, err := os.ReadFile(filepath.Join(pathName, "cmdline"))
		if err != nil {
			continue
		}
		if string(cmdline) == "" {
			continue
		}

		pid, err := proc.GetProcPid(d.Name())
		if err != nil {
			logger.GetLogger().WithError(err).Debugf("pid read error")
			continue
		}

		socketFds, _ := getSocketFdsFromProcDir(pathName)
		if socketFds != nil {
			procSocketFds[uint32(pid)] = socketFds
		}
	}

	return procSocketFds, nil
}

func getFdLookupPrograms() []*program.Program {
	var progs []*program.Program

	if !kernels.MinKernelVersion("5.15.0") {
		if utils.SupportFentry() {
			progs = append(progs, FdLookupFentry)
		} else {
			progs = append(progs, FdLookupKprobe)
		}
	} else {
		if runtime.GOARCH != "amd64" {
			if utils.SupportFentry() {
				progs = append(progs, FdLookupFentry)
			} else {
				progs = append(progs, FdLookupKprobe)
			}
		} else {
			if utils.SupportFentry() {
				progs = append(progs, FdLookupFentry_5_15)
			} else {
				progs = append(progs, FdLookupKprobe_5_15)
			}
		}
	}

	return progs
}

func getFdLookupMaps() []*program.Map {
	var maps []*program.Map

	if utils.SupportFentry() {
		maps = append(maps, FdLookupConfigMapFentry, SocketCookieMapFentry, SocketCookieStatsFentry, VerMapFentry,
			SocketTupleMapFentry, SocketTupleMapStatsFentry, SocketTupleRevMapFentry, SocketTupleHintMapFentry, TcpSocketMapFentry, CfgMapFentry)
	} else {
		maps = append(maps, FdLookupConfigMapKprobe, SocketCookieMapKprobe, SocketCookieStatsKprobe, VerMapKprobe,
			SocketTupleMapKprobe, SocketTupleMapStatsKprobe, SocketTupleRevMapKprobe, SocketTupleHintMapKprobe, TcpSocketMapKprobe, CfgMapKprobe)
	}
	if kernels.MinKernelVersion("5.14.0") {
		if runtime.GOARCH == "amd64" {
			maps = append(maps, []*program.Map{
				program.MapUserFrom(base.EndpointIdMap),
				program.MapUserFrom(base.BpfEndpointIdMap),
				program.MapUserFrom(base.ProcessTreeMap),
				program.MapUserFrom(base.ProcessTreeBinaryUUIDMap),
				program.MapUserFrom(base.ProcessTreeUUIDBinaryMap),
				program.MapUserFrom(base.DestinationEndpointMap),
				program.MapUserFrom(base.ListenEndpointMap),
			}...)
			if utils.SupportFentry() {
				maps = append(maps, []*program.Map{ProcessTreeIdMapFentry}...)
			} else {
				maps = append(maps, []*program.Map{ProcessTreeIdMapKprobe}...)
			}
		}
	}

	return maps
}

func LoadSockets(callback FdCallback, protocol uint16, hint uint64) error {
	/* Load existing network sockets. This consists of: using a BPF program to respond to reading /proc
	 * "comm" files"; exercising it once per socket that was previously discovered in order to load it
	 * into the socket cookie map; and then unloading the BPF program.
	 * This needs to happen before the sensors are loaded, as those sensors depend upon this map
	 * being already populated.
	 */

	procSocketFds, err := getExistingSockets()
	if err != nil {
		logger.GetLogger().WithError(err).Warn("Unable to get existing sockets")
		return err
	}
	writeSocketCookies(procSocketFds, callback, protocol, hint)

	return nil
}

func openConfigMap() *ebpf.Map {
	mapDir := bpf.MapPrefixPath()

	var fdLookupMapPath string
	if utils.SupportFentry() {
		fdLookupMapPath = filepath.Join(mapDir, FdLookupConfigMapFentry.PinPath)
	} else {
		fdLookupMapPath = filepath.Join(mapDir, FdLookupConfigMapKprobe.PinPath)
	}

	m, err := ebpf.LoadPinnedMap(fdLookupMapPath, nil)
	for i := 0; err != nil; i++ {
		m, err = ebpf.LoadPinnedMap(fdLookupMapPath, nil)
		if err != nil {
			time.Sleep(mapRetryDelay * time.Second)
		}
		if i > maxMapRetries {
			logger.GetLogger().WithError(err).Warn("Unable to access FD Lookup Config map.")
			return nil
		}
	}
	return m
}

func getIpAddrPort(ipPort string, ipv6 bool) ([2]uint64, uint16, error) {
	fields := strings.Split(ipPort, ":")
	port, err := strconv.ParseUint(fields[1], 16, 16)
	if err != nil {
		return [2]uint64{0, 0}, 0, err
	}
	ip := fields[0]
	var ipOut [2]uint64
	if ipv6 {
		ip1, err := strconv.ParseUint(ip[0:8], 16, 32)
		if err != nil {
			return ipOut, 0, err
		}
		ip2, err := strconv.ParseUint(ip[8:16], 16, 32)
		if err != nil {
			return ipOut, 0, err
		}
		ip3, err := strconv.ParseUint(ip[16:24], 16, 32)
		if err != nil {
			return ipOut, 0, err
		}
		ip4, err := strconv.ParseUint(ip[24:], 16, 32)
		if err != nil {
			return ipOut, 0, err
		}

		ipOut[0] = (ip2 << 32) | ip1
		ipOut[1] = (ip4 << 32) | ip3
	} else {
		ip1, err := strconv.ParseUint(ip, 16, 32)
		if err != nil {
			return ipOut, 0, err
		}
		ipOut[0] = ip1
	}
	return ipOut, uint16(port), nil
}

func getSocketsForNsFromFile(sockets *map[uint64]networkapi.FdLookupValue, netFile string, protocol uint16) error {
	fileBytes, err := os.ReadFile(netFile)
	if err != nil {
		return err
	}
	ipv6 := netFile[len(netFile)-1] == '6'
	fileString := string(fileBytes)
	fileLines := strings.Split(fileString, "\n")[1:]
	for _, line := range fileLines {
		entries := strings.Fields(line)
		if len(entries) == 0 {
			continue
		}
		if len(entries) < 12 {
			logger.GetLogger().WithFields(logrus.Fields{"len": len(entries), "netFile": netFile}).Info("split")
			return fmt.Errorf("net file does not contain pointer")
		}
		cookie, err := strconv.ParseUint(entries[11], 16, 64)
		if err != nil {
			return err
		}
		inode, err := strconv.ParseUint(entries[9], 10, 64)
		if err != nil {
			return err
		}
		state, err := strconv.ParseUint(entries[3], 16, 8)
		if err != nil {
			return err
		}
		if protocol == syscall.IPPROTO_TCP {
			if state != unix.BPF_TCP_ESTABLISHED && state != unix.BPF_TCP_LISTEN {
				continue
			}
		} else if protocol == syscall.IPPROTO_UDP {
			if state != unix.BPF_TCP_CLOSE && state != unix.BPF_TCP_ESTABLISHED {
				continue
			}
		}
		saddr, sport, err := getIpAddrPort(entries[1], ipv6)
		if err != nil {
			return err
		}
		daddr, dport, err := getIpAddrPort(entries[2], ipv6)
		if err != nil {
			return err
		}
		var ipv6char uint8
		if ipv6 {
			ipv6char = 1
		} else {
			ipv6char = 0
		}
		(*sockets)[inode] = networkapi.FdLookupValue{
			Sockaddr: cookie,
			State:    uint8(state),
			Tuple: networkapi.MsgIPTuple{
				SAddr: saddr,
				SPort: sport,
				DAddr: daddr,
				DPort: dport,
				IPv6:  ipv6char,
			},
			Protocol: protocol,
		}
	}
	return nil
}

func getSocketsForNs(sockets *map[uint64]networkapi.FdLookupValue, netPath string, protocol uint16) error {
	var socketFiles []string
	switch protocol {
	case syscall.IPPROTO_TCP:
		socketFiles = append(socketFiles, "tcp", "tcp6")
	case syscall.IPPROTO_UDP:
		socketFiles = append(socketFiles, "udp", "udp6")
	case syscall.IPPROTO_ICMP:
		socketFiles = append(socketFiles, "icmp", "icmp6")
	case syscall.IPPROTO_RAW:
		socketFiles = append(socketFiles, "raw", "raw6")
	}

	for _, file := range socketFiles {
		err := getSocketsForNsFromFile(sockets, filepath.Join(netPath, file), protocol)
		if err != nil {
			return err
		}
	}
	return nil
}

func GetAndAddSocketViaProc(pid uint32, fd uint32, protocol uint16, m *ebpf.Map) (networkapi.FdLookupValue, error) {
	access.Lock()
	defer access.Unlock()
	return getAndAddSocketViaProc(pid, fd, protocol, m)
}

func getAndAddSocketViaProc(pid uint32, fd uint32, protocol uint16, m *ebpf.Map) (networkapi.FdLookupValue, error) {
	if m == nil {
		m = openConfigMap()
		if m == nil {
			return networkapi.FdLookupValue{}, fmt.Errorf("could not open fd lookup config map")
		}
		defer m.Close()
	}

	sockets := make(map[uint64]networkapi.FdLookupValue)
	err := getSocketsForNs(&sockets, filepath.Join(option.Config.ProcFS, fmt.Sprintf("%d", pid), "net"), protocol)
	if err != nil {
		return networkapi.FdLookupValue{}, err
	}
	fdLink, err := os.Readlink(filepath.Join(option.Config.ProcFS, fmt.Sprintf("%d/fd/%d", pid, fd)))
	if err != nil {
		return networkapi.FdLookupValue{}, err
	}
	fdInode := uint64(0)
	if strings.HasPrefix(fdLink, "socket:[") {
		fdInode, err = strconv.ParseUint(fdLink[8:len(fdLink)-1], 10, 64)
		if err != nil {
			return networkapi.FdLookupValue{}, err
		}
	} else if strings.HasPrefix(fdLink, "[0000]:") {
		fdInode, err = strconv.ParseUint(fdLink[7:], 10, 64)
		if err != nil {
			return networkapi.FdLookupValue{}, err
		}
	}
	var ok bool
	socket, ok := sockets[fdInode]
	if !ok {
		return networkapi.FdLookupValue{}, fmt.Errorf("socket not found in process namespace")
	}
	// Add the socket
	socket.Pid = pid
	socket.Fd = fd

	k := &networkapi.FdLookupKey{Zero: 0}
	m.Put(k, &socket)
	/* Trigger BPF FD Lookup program.
	 * The approach taken here (and later in writeSocketCookies and GetSocketForFD) is to hook
	 * proc_task_name, which is called whenever user space accesses the /proc/PID/comm pseudo-files.
	 * This hook receives a pointer to the target task_struct as an argument, and this task_struct
	 * can be mined for the provided file descriptor.
	 *
	 * Later in writeSocketCookies and GetSocketForFD we use the same approach to obtain the socket
	 * details, including the pseudo socket cookie (used for linking a socket to a process).
	 *
	 * We make the assumption that /procRoot (option.Config.ProcFS) is bound to the host's /proc
	 * so the PIDs in it are host-wide PIDs, rather than namespaced PIDs. This is important so we
	 * can match up the process in /procRoot with the process in BPF (the PIDs will match).
	 */

	os.ReadFile(filepath.Join(option.Config.ProcFS, fmt.Sprintf("%d", pid), "comm"))
	return socket, nil
}

func writeSocketCookies(procSocketFds map[uint32][]uint32, callback FdCallback, protocol uint16, hint uint64) {
	access.Lock()
	defer access.Unlock()

	m := openConfigMap()
	if m == nil {
		return
	}
	defer m.Close()

	numIterations := 10
	for pid, fds := range procSocketFds {
		cgid, _ := cgroups.CgroupIDFromPID(pid)
		for _, fd := range fds {
			k := &networkapi.FdLookupKey{Zero: 0}
			v := &networkapi.FdLookupValue{
				Pid:       pid,
				Fd:        fd,
				Protocol:  protocol,
				CgrpId:    cgid,
				SignalHit: 0,
				Hint:      hint,
			}
			m.Put(k, v)
			for loadWait := 0; loadWait < numIterations; loadWait++ {
				// See GetAndAddSocketViaProc for details on how this works.
				os.ReadFile(filepath.Join(option.Config.ProcFS, fmt.Sprintf("%d", pid), "comm"))
				err := m.Lookup(k, v)
				if err == nil {
					if v.SignalHit == 1 {
						break
					}
				}
				// Need a little wait to allow the probe to be attached (only
				// applies to first iteration of outer loop).
				time.Sleep(10 * time.Millisecond)
			}

			var socket networkapi.FdLookupValue
			if int16(v.Protocol) == -1 {
				// This indicates a read error in BPF, so reread via /proc.
				var err error
				socket, err = getAndAddSocketViaProc(pid, fd, protocol, m)
				if err != nil {
					logger.GetLogger().WithError(err).WithFields(logrus.Fields{"pid": pid, "fd": fd, "protocol": protocol}).Debug("Socket discovery failed")
					continue
				}
				v = &socket
			}

			if v.Protocol == protocol && callback != nil {
				callback(v, pid)
			}
			// Should only need multiple attempts on first call
			numIterations = 1
		}
	}
}

func GetSocketForFD(protocol uint16, pid int, fd int, cookie uint64, family int) uint64 {
	access.Lock()
	defer access.Unlock()

	socket := uint64(0)

	m := openConfigMap()
	if m == nil {
		return 0
	}
	defer m.Close()

	k := &networkapi.FdLookupKey{Zero: 0}
	v := &networkapi.FdLookupValue{
		Pid:       uint32(pid),
		Fd:        uint32(fd),
		Protocol:  protocol,
		SignalHit: 0,
		Sockaddr:  cookie,
		Family:    uint16(family),
	}
	m.Put(k, v)
	for loadWait := 0; loadWait < 10; loadWait++ {
		// See GetAndAddSocketViaProc for details on how this works.
		os.ReadFile(filepath.Join(option.Config.ProcFS, fmt.Sprintf("%d", pid), "comm"))
		err := m.Lookup(k, v)
		if err == nil {
			if v.SignalHit == 1 {
				break
			}
		}
		// Need a little wait to allow the probe to be attached.
		time.Sleep(10 * time.Millisecond)
	}

	if v.Protocol == protocol {
		socket = v.Sockaddr
	}

	return socket
}
