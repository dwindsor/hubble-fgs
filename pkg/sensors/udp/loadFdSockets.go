//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package udp

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/proc"
	"github.com/isovalent/hubble-fgs/pkg/observer"
	"github.com/isovalent/hubble-fgs/pkg/sensors"
)

const (
	maxMapRetries  = 4
	mapRetryDelay  = 1
	fdLookupSignal = 1024
)

type fdLookupKey struct {
	Zero uint32
}

type fdLookupValue struct {
	Pid uint32
	Fd  uint32
}

func (k *fdLookupKey) String() string             { return fmt.Sprintf("key=%d", k.Zero) }
func (k *fdLookupKey) GetKeyPtr() unsafe.Pointer  { return unsafe.Pointer(k) }
func (k *fdLookupKey) DeepCopyMapKey() bpf.MapKey { return &fdLookupKey{k.Zero} }

func (k *fdLookupKey) NewValue() bpf.MapValue { return &fdLookupValue{} }

func (v *fdLookupValue) String() string {
	return fmt.Sprintf("value=%d %d", v.Pid, v.Fd)
}
func (v *fdLookupValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }
func (v *fdLookupValue) DeepCopyMapValue() bpf.MapValue {
	return &fdLookupValue{}
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

func getFdLookupPrograms() []*sensors.Program {
	progs := []*sensors.Program{FdLookup}
	return progs
}

func getFdLookupMaps() []*sensors.Map {
	var maps []*sensors.Map

	maps = append(maps, FdLookupConfigMap, SocketCookieMap)

	return maps
}

func getOnlyFdLookupMaps() []*sensors.Map {
	var maps []*sensors.Map

	maps = append(maps, FdLookupConfigMap)

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

func loadSockets() error {
	/* Load existing network sockets. This consists of: loading a BPF program to respond to kill
	 * syscalls; exercising it once per socket that was previously discovered in order to load it
	 * into the socket cookie map; and then unloading the BPF program.
	 * This needs to happen before the sensors are loaded, as those sensors depend upon this map
	 * being already populated.
	 */
	procSocketFds, err := getExistingSockets()
	if err != nil {
		logger.GetLogger().WithError(err).Warn("Unable to get existing sockets")
		return err
	}
	fdLoadSensor, err := loadFdLookup(observer.GetBpfDir(), observer.GetMapDir(), observer.GetCiliumDir())
	if err != nil {
		logger.GetLogger().WithError(err).Warn("Unable to load FD Lookup program")
		return err
	}
	writeSocketCookies(procSocketFds)
	if err := unloadFdLookup(fdLoadSensor, observer.GetBpfDir(), observer.GetMapDir(), observer.GetCiliumDir()); err != nil {
		logger.GetLogger().WithError(err).Warn("Unable to unload FD Lookup program")
		return err
	}

	return nil
}

func writeSocketCookies(procSocketFds map[uint32][]uint32) {
	mapDir := bpf.MapPrefixPath()

	fdLookupMap := FdLookupConfigMap

	if fdLookupMap.PinState.IsDisabled() {
		logger.GetLogger().Infof("hubble-fgs, map %s is disabled, skipping.", fdLookupMap.Name)
		return
	}

	m, err := bpf.OpenMap(filepath.Join(mapDir, fdLookupMap.Name))
	for i := 0; err != nil; i++ {
		m, err = bpf.OpenMap(filepath.Join(mapDir, fdLookupMap.Name))
		if err != nil {
			time.Sleep(mapRetryDelay * time.Second)
		}
		if i > maxMapRetries {
			logger.GetLogger().WithError(err).Warn("Unable to access FD Lookup Config map.")
			return
		}
	}
	for pid, fds := range procSocketFds {
		for _, fd := range fds {
			k := &fdLookupKey{Zero: 0}
			v := &fdLookupValue{
				Pid: pid,
				Fd:  fd,
			}
			m.Update(k, v)
			syscall.Syscall(syscall.SYS_KILL, uintptr(pid), fdLookupSignal, 0)
		}
	}
	m.Close()
}
