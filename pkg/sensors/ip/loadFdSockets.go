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
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/proc"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
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
	Pid                uint32
	Fd                 uint32
	Sockaddr           uint64
	Saddr              [2]uint64
	Daddr              [2]uint64
	Sport              uint16
	Dport              uint16
	Protocol           uint16
	State              uint8
	IPv6               uint8
	DiscoverProtoShift uint8
	ProtoShift         uint8
	Pad1               uint16
	Pad2               uint32
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

	// Socket lookup config map
	FdLookupConfigMap = program.MapBuilder(FdLookupConfigMapName, FdLookup)

	// Shared socket cookie infrastructure
	SocketCookieMap    = program.MapBuilder(SocketMapName, FdLookup)
	SocketCookieStats  = program.MapBuilder(SocketMapStatsName, FdLookup)
	TlsSocketCookieMap = program.MapBuilder(TlsSocketMapName, FdLookup)

	// Detection of protocol shift
	protocolShiftDetected = false
	protocolShift         = false
	gettingProtocolShift  = false
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

	progs = append(progs, FdLookup)

	if !gettingProtocolShift {
		// Ensure we have already got the protocol shift value, or use this
		// opportunity to go and get it before doing anything else.
		_, err := getProtocolShift()

		if err != nil {
			logger.GetLogger().Warn("Could not detect protocol shift")
		}
	}

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

func ProtocolShift() (bool, error) {
	/* Detects whether the protocol field in struct sock needs shifting or not.
	 * This is detected by loading the FD lookup on a specific known FD.
	 */
	loading.Lock()
	defer loading.Unlock()

	return getProtocolShift()
}

func getProtocolShift() (bool, error) {
	/* Detects whether the protocol field in struct sock needs shifting or not.
	 * This is detected by loading the FD lookup on a specific known FD.
	 * Internal version that doesn't need a lock because we should already be
	 * locked. ONLY call from a function that gets the loading.Lock()
	 */

	/* First, has it already been detected?
	 */
	if protocolShiftDetected {
		return protocolShift, nil
	}

	/* Next, check if we have overridden the discovery.
	 */
	if enterpriseOption.Config.ProtocolShift == enterpriseOption.ShiftTrue {
		protocolShift = true
		protocolShiftDetected = true
		return true, nil
	} else if enterpriseOption.Config.ProtocolShift == enterpriseOption.ShiftFalse {
		protocolShift = false
		protocolShiftDetected = true
		return false, nil
	}

	gettingProtocolShift = true

	logger.GetLogger().Info("Detecting protocol shift with FD Lookup")

	fdLoadSensor, err := loadFdLookup(option.Config.BpfDir, option.Config.MapDir, option.Config.CiliumDir)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("Unable to load FD Lookup program")
		return false, fmt.Errorf("unable to load FD Lookup program")
	}

	defer unloadFdLookup(fdLoadSensor, option.Config.BpfDir, option.Config.MapDir, option.Config.CiliumDir)

	m := openConfigMap()
	if m == nil {
		return false, fmt.Errorf("unable to open FD Lookup map")
	}

	// Create a listener
	syscall.ForkLock.Lock()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	syscall.ForkLock.Unlock()
	if err != nil {
		logger.GetLogger().WithError(err).Warn("Unable to create socket for FD Lookup")
		return false, fmt.Errorf("unable to create socket for FD Lookup")
	}
	defer syscall.Close(fd)

	sa := &syscall.SockaddrInet4{Port: 7112, Addr: [4]byte{0, 0, 0, 0}}
	err = syscall.Bind(fd, sa)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("Unable to bind socket for FD Lookup")
		return false, fmt.Errorf("unable to bind socket for FD Lookup")
	}

	pid := os.Getpid()

	k := &FdLookupKey{Zero: 0}
	v := &FdLookupValue{
		Pid:                uint32(pid),
		Fd:                 uint32(fd),
		Protocol:           syscall.IPPROTO_UDP,
		DiscoverProtoShift: 1,
	}
	m.Update(k, v)
	syscall.Syscall(syscall.SYS_KILL, uintptr(pid), fdLookupSignal, 0)
	ret, err := m.Lookup(k)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("FD Lookup could not access config map")
		return false, fmt.Errorf("fd lookup could not access config map")
	}
	v = ret.(*FdLookupValue)

	if v.DiscoverProtoShift != 0 {
		logger.GetLogger().WithField("DiscoverProtoShift", v.DiscoverProtoShift).Warn("FD Lookup could not detect protocol shift")
		return false, fmt.Errorf("fd lookup could not detect protocol shift")

	}

	if v.ProtoShift != 0 && v.ProtoShift != 1 {
		logger.GetLogger().WithError(err).Warn("FD Lookup protocol shift could not be determined")
		return false, fmt.Errorf("fd lookup protocol shift could not be determined")
	}
	protocolShift = v.ProtoShift == 1
	protocolShiftDetected = true

	logger.GetLogger().Infof("Protocol shift detected: %v", protocolShift)

	gettingProtocolShift = false

	return protocolShift, nil
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
				Pid:                pid,
				Fd:                 fd,
				Protocol:           protocol,
				DiscoverProtoShift: 0,
			}
			if protocolShift {
				v.ProtoShift = 1
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
		Pid:                uint32(pid),
		Fd:                 uint32(fd),
		Protocol:           protocol,
		DiscoverProtoShift: 0,
	}
	if protocolShift {
		v.ProtoShift = 1
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

func ConfigureProtocolShift(mapDir string) error {
	m, err := bpf.OpenMap(filepath.Join(mapDir, FdLookupConfigMapName))
	if err != nil {
		return err
	}
	defer m.Close()

	key := &FdLookupKey{
		Zero: uint32(0),
	}
	config := &FdLookupValue{}
	if protocolShift {
		config.ProtoShift = 1
	}
	m.Update(key, config)
	logger.GetLogger().Infof("Configured protocol shift: %t", protocolShift)
	return nil
}
