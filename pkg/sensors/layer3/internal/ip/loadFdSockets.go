// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package ip

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/cgroups"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/proc"
	"github.com/cilium/tetragon/pkg/sensors/program"

	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/constants"
	"github.com/isovalent/hubble-fgs/pkg/dnsparser"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
)

const (
	maxMapRetries         = 4
	mapRetryDelay         = 1
	FdLookupConfigMapName = "tg_l3_sk_lookup"
	SocketMapName         = "tg_l3_sk"
	SocketMapStatsName    = "tg_l3_sk_stats"
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

	FdLookupKprobeProcessTree = program.Builder(
		"bpf_fd_lookup_pstree.o",
		"proc_task_name",
		"kprobe/proc_task_name",
		"kprobe_proc_task_name",
		"layer3_sensor",
	)

	FdLookupFentryProcessTree = program.Builder(
		"bpf_fd_lookup_fentry_pstree.o",
		"fentry",
		"fentry/proc_task_name",
		"fentry_proc_task_name",
		"layer3_sensor",
	)

	// All the FdLookup sensor maps below are accessed from other sensors,
	// so they need to stay global as is expected by its users.

	// Socket lookup config map
	FdLookupConfigMap = program.MapBuilder(FdLookupConfigMapName, FdLookupKprobe, FdLookupFentry, FdLookupKprobeProcessTree, FdLookupFentryProcessTree)

	// Endpoint Models
	ProcessTreeIdMap = program.MapUserFrom(base.ProcessTreeId)

	// Shared socket cookie infrastructure
	SocketMap           = program.MapUserFrom(base.SocketMap)
	SocketMapStats      = program.MapUserFrom(base.SocketStats)
	SocketVersionMap    = program.MapUserFrom(base.SocketVersionMap)
	SocketTupleMap      = program.MapUserFrom(base.SocketTupleMap)
	SocketTupleMapStats = program.MapUserFrom(base.SocketTupleStats)
	SocketTupleRevMap   = program.MapUserFrom(base.SocketTupleRevMap)
	SocketTupleHintMap  = program.MapUserFrom(base.SocketTupleHintMap)
	ConfigMap           = program.MapUserFrom(base.CfgMap)

	// Shared base maps
	ExecveMap = program.MapUserFrom(base.ExecveMap)

	// LPM maps
	Addr6LpmMap = program.MapUserFrom(base.Addr6LpmMap)
	Addr4LpmMap = program.MapUserFrom(base.Addr4LpmMap)

	// TCP maps
	TcpSocketMap      = program.MapUserFrom(base.TcpSocketMap)
	TcpSocketMapStats = program.MapUserFrom(base.TcpSocketMapStats)

	// DNS parsers maps, shared between process tree and the parser
	DNSIPToIDMaps        = program.MapBuilder(dnsparser.IPToIDMapsName, FdLookupKprobeProcessTree, FdLookupFentryProcessTree)
	AllocationIDMap      = program.MapBuilder(dnsparser.AllocationIDMapName, FdLookupKprobeProcessTree, FdLookupFentryProcessTree)
	CgroupIDToAllocIDMap = program.MapBuilder(dnsparser.CgroupIDToAllocIDMapName, FdLookupKprobeProcessTree, FdLookupFentryProcessTree)
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
		logger.GetLogger().Error("Could not read directory "+option.Config.ProcFS, logfields.Error, err)
		return nil, err
	}

	for _, d := range procFS {
		if !d.IsDir() {
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
			logger.GetLogger().Debug("pid read error", logfields.Error, err)
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

	if !utils.SupportProcessTree() {
		if utils.SupportFentry() {
			progs = append(progs, FdLookupFentry)
		} else {
			progs = append(progs, FdLookupKprobe)
		}
	} else {
		if utils.SupportFentry() {
			if enterpriseOption.Config.EnableBPFDNSPerPod {
				err := dnsparser.RewritePerPodConstants(FdLookupFentryProcessTree.RewriteConstants)
				if err != nil {
					// TODO: when we remove enabling layer3 from CRD, return this error and stop init of sensor
					logger.GetLogger().Error("Failed to rewrite DNS parser constants", logfields.Error, err)
				}
			}
			progs = append(progs, FdLookupFentryProcessTree)
		} else {
			progs = append(progs, FdLookupKprobeProcessTree)
		}
	}

	return progs
}

func getFdLookupMaps() []*program.Map {
	maps := []*program.Map{
		FdLookupConfigMap,
		SocketMap,
		SocketMapStats,
		SocketVersionMap,
		SocketTupleMap,
		SocketTupleMapStats,
		SocketTupleRevMap,
		SocketTupleHintMap,
		ConfigMap,
		ExecveMap,
		TcpSocketMap,
		TcpSocketMapStats,
		DNSIPToIDMaps,
		AllocationIDMap,
		CgroupIDToAllocIDMap,
	}

	if utils.SupportProcessTree() {
		maps = append(maps, []*program.Map{
			program.MapUserFrom(base.EndpointIdMap),
			program.MapUserFrom(base.BpfEndpointIdMap),
			program.MapUserFrom(base.ProcessTreeMap),
			program.MapUserFrom(base.ProcessTreeBinaryUUIDMap),
			program.MapUserFrom(base.DestinationEndpointMap),
			program.MapUserFrom(base.ListenEndpointMap),
			program.MapUserFrom(base.PidDataMap),
			ProcessTreeIdMap,
			Addr4LpmMap,
			Addr6LpmMap,
		}...)

	}

	if enterpriseOption.Config.EnableBPFDNSParser {
		DNSIPToIDMaps.SetMaxEntries(dnsparser.MaxNumberOfPods)

		if enterpriseOption.Config.EnableBPFDNSPerPod {
			CgroupIDToAllocIDMap.SetMaxEntries(dnsparser.MaxNumberOfPods)
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
		logger.GetLogger().Warn("Unable to get existing sockets", logfields.Error, err)
		return err
	}
	writeSocketCookies(procSocketFds, callback, protocol, hint)

	return nil
}

func openConfigMap() *ebpf.Map {
	mapDir := bpf.MapPrefixPath()

	fdLookupMapPath := filepath.Join(mapDir, FdLookupConfigMap.PinPath)

	m, err := ebpf.LoadPinnedMap(fdLookupMapPath, nil)
	for i := 0; err != nil; i++ {
		m, err = ebpf.LoadPinnedMap(fdLookupMapPath, nil)
		if err != nil {
			time.Sleep(mapRetryDelay * time.Second)
		}
		if i > maxMapRetries {
			logger.GetLogger().Warn("Unable to access FD Lookup Config map.", logfields.Error, err)
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
			logger.GetLogger().Info("split", "len", len(entries), "netFile", netFile)
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
			if state != constants.BPF_TCP_ESTABLISHED && state != constants.BPF_TCP_LISTEN {
				continue
			}
		} else if protocol == syscall.IPPROTO_UDP {
			if state != constants.BPF_TCP_CLOSE && state != constants.BPF_TCP_ESTABLISHED {
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
	case constants.IPPROTO_ICMP:
		socketFiles = append(socketFiles, "icmp", "icmp6")
	case constants.IPPROTO_RAW:
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
					logger.GetLogger().Debug("Socket discovery failed", logfields.Error, err, "pid", pid, "fd", fd, "protocol", protocol)
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
