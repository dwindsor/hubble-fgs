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
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/proc"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

const (
	maxMapRetries         = 4
	mapRetryDelay         = 1
	fdLookupSignal        = 1024
	FdLookupConfigMapName = "fd_lookup_config_map"
	SocketMapName         = "socket_map"
	TlsSocketMapName      = "tls_socket_map"
	SocketMapStatsName    = "socket_map_stats"
)

type FdLookupKey struct {
	Zero uint32
}

type FdLookupValue struct {
	Pid      uint32
	Fd       uint32
	Sockaddr uint64
	Saddr    [2]uint64
	Daddr    [2]uint64
	Sport    uint16
	Dport    uint16
	Protocol uint16
	State    uint8
	IPv6     uint8
}

type FdCallback func(*FdLookupValue, uint32)

var (
	// Mutex to prevent concurrent loading
	loading sync.Mutex

	// Socket lookup program
	FdLookup = program.Builder(
		"bpf_fd_lookup.o",
		"check_kill_permission",
		"kprobe/check_kill_permission",
		"kprobe_check_kill_permission",
		"kprobe",
	)

	FdLookupV56 = program.Builder(
		"bpf_fd_lookup_v56.o",
		"check_kill_permission",
		"kprobe/check_kill_permission",
		"kprobe_check_kill_permission",
		"kprobe",
	)

	// Socket lookup config map
	FdLookupConfigMap    = program.MapBuilder(FdLookupConfigMapName, FdLookup)
	FdLookupConfigMapV56 = program.MapBuilder(FdLookupConfigMapName, FdLookupV56)

	// Shared socket cookie infrastructure
	SocketCookieMap       = program.MapBuilder(SocketMapName, FdLookup)
	SocketCookieMapV56    = program.MapBuilder(SocketMapName, FdLookupV56)
	SocketCookieStats     = program.MapBuilder(SocketMapStatsName, FdLookup)
	SocketCookieStatsV56  = program.MapBuilder(SocketMapStatsName, FdLookupV56)
	TlsSocketCookieMap    = program.MapBuilder(TlsSocketMapName, FdLookup)
	TlsSocketCookieMapV56 = program.MapBuilder(TlsSocketMapName, FdLookupV56)
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
	fds, err := ioutil.ReadDir(filepath.Join(dirname, "fd"))
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

	procFS, err := ioutil.ReadDir(option.Config.ProcFS)
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
		cmdline, err := ioutil.ReadFile(filepath.Join(pathName, "cmdline"))
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
	if !kernels.MinKernelVersion("5.6.0") {
		progs = append(progs, FdLookup)
	} else {
		progs = append(progs, FdLookupV56)
	}
	return progs
}

func getFdLookupMaps() []*program.Map {
	var maps []*program.Map

	if !kernels.MinKernelVersion("5.6.0") {
		maps = append(maps, FdLookupConfigMap, SocketCookieMap, TlsSocketCookieMap, SocketCookieStats)
	} else {
		maps = append(maps, FdLookupConfigMapV56, SocketCookieMapV56, TlsSocketCookieMapV56, SocketCookieStatsV56)
	}

	return maps
}

func getOnlyFdLookupMaps() []*program.Map {
	var maps []*program.Map

	if !kernels.MinKernelVersion("5.6.0") {
		maps = append(maps, FdLookupConfigMap)
	} else {
		maps = append(maps, FdLookupConfigMapV56)
	}

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
	if err := fdLoadSensor.Load(context.TODO(), bpfDir, mapDir, ciliumDir); err != nil {
		return nil, fmt.Errorf("hubble-fgs, aborting could not load BPF programs: %w", err)
	}
	return fdLoadSensor, nil
}

func unloadFdLookup(fdLoadSensor *sensors.Sensor, bpfDir, mapDir, ciliumDir string) error {
	if fdLoadSensor == nil {
		return fmt.Errorf("hubble-fgs, could not unload BPF programs: fdLoadSensor")
	}
	fdLoadSensor.Maps = getOnlyFdLookupMaps()
	if err := sensors.UnloadSensor(context.TODO(), bpfDir, mapDir, fdLoadSensor); err != nil {
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

func writeSocketCookies(procSocketFds map[uint32][]uint32, callback FdCallback, protocol uint16) {
	m := openConfigMap()
	if m == nil {
		return
	}
	for pid, fds := range procSocketFds {
		for _, fd := range fds {
			k := &FdLookupKey{Zero: 0}
			v := &FdLookupValue{
				Pid:      pid,
				Fd:       fd,
				Protocol: protocol,
			}
			m.Update(k, v)
			syscall.Syscall(syscall.SYS_KILL, uintptr(pid), fdLookupSignal, 0)
			ret, err := m.Lookup(k)
			if err == nil {
				v = ret.(*FdLookupValue)
				if v.Protocol == protocol && callback != nil {
					callback(v, pid)
				}
			}
		}
	}
	m.Close()
}

func GetSocketForFD(protocol uint16, pid int, fd int) uint64 {
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

	k := &FdLookupKey{Zero: 0}
	v := &FdLookupValue{
		Pid:      uint32(pid),
		Fd:       uint32(fd),
		Protocol: protocol,
	}
	m.Update(k, v)
	syscall.Syscall(syscall.SYS_KILL, uintptr(pid), fdLookupSignal, 0)
	ret, err := m.Lookup(k)
	if err == nil {
		v = ret.(*FdLookupValue)
		if v.Protocol == protocol {
			socket = v.Sockaddr
		}
	}
	if err := unloadFdLookup(fdLoadSensor, option.Config.BpfDir, option.Config.MapDir, option.Config.CiliumDir); err != nil {
		logger.GetLogger().WithError(err).Warn("Unable to unload FD Lookup program")
	}

	return socket
}
