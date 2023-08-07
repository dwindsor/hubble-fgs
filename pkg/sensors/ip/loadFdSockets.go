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
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/proc"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const (
	maxMapRetries         = 4
	mapRetryDelay         = 1
	FdLookupConfigMapName = "fd_lookup_config_map"
	SocketMapName         = "tg_socket_map"
	TlsSocketMapName      = "tg_tls_socket_map"
	SocketMapStatsName    = "tg_socket_map_stats"
)

type FdLookupKey struct {
	Zero uint32
}

type FdLookupValue struct {
	Pid       uint32
	Fd        uint32
	Sockaddr  uint64
	Saddr     [2]uint64
	Daddr     [2]uint64
	Sport     uint16
	Dport     uint16
	Protocol  uint16
	State     uint8
	IPv6      uint8
	SignalHit uint8
	Pad1      uint8
	Family    uint16
	Pad2      uint16
	Pad3      uint16
}

type FdCallback func(*FdLookupValue, uint32)

var (
	// Mutex to prevent concurrent loading
	loading sync.Mutex

	// Socket lookup program
	FdLookup = program.Builder(
		"bpf_fd_lookup.o",
		"proc_task_name",
		"kprobe/proc_task_name",
		"kprobe_proc_task_name",
		"kprobe",
	)

	// Socket lookup config map
	FdLookupConfigMap = program.MapBuilder(FdLookupConfigMapName, FdLookup)

	// Shared socket cookie infrastructure
	SocketCookieMap    = program.MapBuilder(SocketMapName, FdLookup)
	SocketCookieStats  = program.MapBuilder(SocketMapStatsName, FdLookup)
	TlsSocketCookieMap = program.MapBuilder(TlsSocketMapName, FdLookup)
)

func (k *FdLookupKey) String() string             { return fmt.Sprintf("key=%d", k.Zero) }
func (k *FdLookupKey) GetKeyPtr() unsafe.Pointer  { return unsafe.Pointer(k) }
func (k *FdLookupKey) DeepCopyMapKey() bpf.MapKey { return &FdLookupKey{k.Zero} }

func (k *FdLookupKey) NewValue() bpf.MapValue { return &FdLookupValue{} }

func (v *FdLookupValue) String() string {
	return fmt.Sprintf("value=%d %d", v.Pid, v.Fd)
}
func (v *FdLookupValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }
func (v *FdLookupValue) DeepCopyMapValue() bpf.MapValue {
	return &FdLookupValue{}
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
			logger.GetLogger().WithError(err).Warnf("pid read error")
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

	progs = append(progs, FdLookup)

	return progs
}

func getFdLookupMaps() []*program.Map {
	var maps []*program.Map

	maps = append(maps, FdLookupConfigMap, SocketCookieMap, TlsSocketCookieMap, SocketCookieStats)

	return maps
}

func getOnlyFdLookupMaps() []*program.Map {
	var maps []*program.Map

	return maps
}

// GetInitialSensor returns the collection of Sensor that is loaded at
// initialization time.
func getFdLookupSensor() *sensors.Sensor {
	return &sensors.Sensor{
		Name:  "FdLookup",
		Progs: getFdLookupPrograms(),
		Maps:  getFdLookupMaps(),
	}
}

// LoadFdLookup loads the kernel oracle.
func loadFdLookup(bpfDir, mapDir, ciliumDir string) (*sensors.Sensor, error) {
	fdLoadSensor := getFdLookupSensor()
	if err := fdLoadSensor.Load(bpfDir, mapDir, ciliumDir); err != nil {
		return nil, fmt.Errorf("hubble-fgs, aborting could not load BPF programs: %w", err)
	}
	return fdLoadSensor, nil
}

func unloadFdLookup(fdLoadSensor *sensors.Sensor, _, _, _ string) error {
	if fdLoadSensor == nil {
		return fmt.Errorf("hubble-fgs, could not unload BPF programs: fdLoadSensor")
	}
	fdLoadSensor.Maps = getOnlyFdLookupMaps()
	if err := fdLoadSensor.Unload(); err != nil {
		return fmt.Errorf("hubble-fgs, could not unload BPF programs: %w", err)
	}
	return nil
}

func LoadSockets(callback FdCallback, protocol uint16) error {
	/* Load existing network sockets. This consists of: loading a BPF program to respond to kill
	 * syscalls; exercising it once per socket that was previously discovered in order to load it
	 * into the socket cookie map; and then unloading the BPF program.
	 * This needs to happen before the sensors are loaded, as those sensors depend upon this map
	 * being already populated.
	 */

	loading.Lock()
	defer loading.Unlock()

	procSocketFds, err := getExistingSockets()
	if err != nil {
		logger.GetLogger().WithError(err).Warn("Unable to get existing sockets")
		return err
	}
	fdLoadSensor, err := loadFdLookup(option.Config.BpfDir, option.Config.MapDir, option.Config.CiliumDir)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("Unable to load FD Lookup program")
		return err
	}
	writeSocketCookies(procSocketFds, callback, protocol)
	if err := unloadFdLookup(fdLoadSensor, option.Config.BpfDir, option.Config.MapDir, option.Config.CiliumDir); err != nil {
		logger.GetLogger().WithError(err).Warn("Unable to unload FD Lookup program")
		return err
	}

	return nil
}

func openConfigMap() *bpf.Map {
	mapDir := bpf.MapPrefixPath()

	fdLookupMap := FdLookupConfigMap

	m, err := bpf.OpenMap(filepath.Join(mapDir, fdLookupMap.Name))
	for i := 0; err != nil; i++ {
		m, err = bpf.OpenMap(filepath.Join(mapDir, fdLookupMap.Name))
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

func getSocketsForNsFromFile(sockets *map[uint64]FdLookupValue, netFile string, protocol uint16) error {
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
		(*sockets)[inode] = FdLookupValue{
			Sockaddr: cookie,
			State:    uint8(state),
			Saddr:    saddr,
			Sport:    sport,
			Daddr:    daddr,
			Dport:    dport,
			Protocol: protocol,
			IPv6:     ipv6char,
		}
	}
	return nil
}

func getSocketsForNs(sockets *map[uint64]FdLookupValue, netPath string, protocol uint16) error {
	var socketFiles []string
	if protocol == syscall.IPPROTO_TCP {
		socketFiles = append(socketFiles, "tcp", "tcp6")
	} else if protocol == syscall.IPPROTO_UDP {
		socketFiles = append(socketFiles, "udp", "udp6")
	}
	for _, file := range socketFiles {
		err := getSocketsForNsFromFile(sockets, filepath.Join(netPath, file), protocol)
		if err != nil {
			return err
		}
	}
	return nil
}

func GetAndAddSocketViaProc(pid uint32, fd uint32, protocol uint16, m *bpf.Map) (FdLookupValue, error) {
	if m == nil {
		m = openConfigMap()
		if m == nil {
			return FdLookupValue{}, fmt.Errorf("could not open fd lookup config map")
		}
		defer m.Close()
	}

	sockets := make(map[uint64]FdLookupValue)
	err := getSocketsForNs(&sockets, filepath.Join(option.Config.ProcFS, fmt.Sprintf("%d", pid), "net"), protocol)
	if err != nil {
		return FdLookupValue{}, err
	}
	fdLink, err := os.Readlink(filepath.Join(option.Config.ProcFS, fmt.Sprintf("%d/fd/%d", pid, fd)))
	if err != nil {
		return FdLookupValue{}, err
	}
	fdInode := uint64(0)
	if strings.HasPrefix(fdLink, "socket:[") {
		fdInode, err = strconv.ParseUint(fdLink[8:len(fdLink)-1], 10, 64)
		if err != nil {
			return FdLookupValue{}, err
		}
	} else if strings.HasPrefix(fdLink, "[0000]:") {
		fdInode, err = strconv.ParseUint(fdLink[7:], 10, 64)
		if err != nil {
			return FdLookupValue{}, err
		}
	}
	var ok bool
	socket, ok := sockets[fdInode]
	if !ok {
		return FdLookupValue{}, fmt.Errorf("socket not found in process namespace")
	}
	// Add the socket
	socket.Pid = pid
	socket.Fd = fd

	k := &FdLookupKey{Zero: 0}
	m.Update(k, &socket)
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

func writeSocketCookies(procSocketFds map[uint32][]uint32, callback FdCallback, protocol uint16) {
	m := openConfigMap()
	if m == nil {
		return
	}
	defer m.Close()

	numIterations := 10
	for pid, fds := range procSocketFds {
		for _, fd := range fds {
			k := &FdLookupKey{Zero: 0}
			v := &FdLookupValue{
				Pid:       pid,
				Fd:        fd,
				Protocol:  protocol,
				SignalHit: 0,
			}
			m.Update(k, v)
			for loadWait := 0; loadWait < numIterations; loadWait++ {
				// See GetAndAddSocketViaProc for details on how this works.
				os.ReadFile(filepath.Join(option.Config.ProcFS, fmt.Sprintf("%d", pid), "comm"))
				ret, err := m.Lookup(k)
				if err == nil {
					v = ret.(*FdLookupValue)
					if v.SignalHit == 1 {
						break
					}
				}
				// Need a little wait to allow the probe to be attached (only
				// applies to first iteration of outer loop).
				time.Sleep(10 * time.Millisecond)
			}

			var socket FdLookupValue
			if v.Protocol == 0 {
				var err error
				socket, err = GetAndAddSocketViaProc(pid, fd, protocol, m)
				if err != nil {
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
	loading.Lock()
	defer loading.Unlock()

	socket := uint64(0)

	fdLoadSensor, err := loadFdLookup(option.Config.BpfDir, option.Config.MapDir, option.Config.CiliumDir)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("Unable to load FD Lookup program")
		return 0
	}

	m := openConfigMap()
	if m == nil {
		return 0
	}
	defer m.Close()

	k := &FdLookupKey{Zero: 0}
	v := &FdLookupValue{
		Pid:       uint32(pid),
		Fd:        uint32(fd),
		Protocol:  protocol,
		SignalHit: 0,
		Sockaddr:  cookie,
		Family:    uint16(family),
	}
	m.Update(k, v)
	for loadWait := 0; loadWait < 10; loadWait++ {
		// See GetAndAddSocketViaProc for details on how this works.
		os.ReadFile(filepath.Join(option.Config.ProcFS, fmt.Sprintf("%d", pid), "comm"))
		ret, err := m.Lookup(k)
		if err == nil {
			v = ret.(*FdLookupValue)
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

	if err := unloadFdLookup(fdLoadSensor, option.Config.BpfDir, option.Config.MapDir, option.Config.CiliumDir); err != nil {
		logger.GetLogger().WithError(err).Warn("Unable to unload FD Lookup program")
	}

	return socket
}
