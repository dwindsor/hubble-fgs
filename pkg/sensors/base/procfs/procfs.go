//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package procfs

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/proc"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/isovalent/hubble-fgs/pkg/api/modelapi"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
)

const (
	procFSConfigMapName  = "tg_procfs_cfg"
	maxMapRetries        = 4
	mapRetryDelay        = 1
	procFSWalkSensorName = "model_procfs_walk"
)

var (
	access sync.Mutex

	ProcFSWalkKprobe = program.Builder(
		"bpf_procfs_walk.o",
		"krobe",
		"kprobe/proc_task_name",
		"kprobe_tg_am_pfs_walk",
		procFSWalkSensorName,
	)

	ProcFSWalkFentry = program.Builder(
		"bpf_procfs_walk_fentry.o",
		"fentry",
		"fentry/proc_task_name",
		"fentry_tg_am_pfs_walk",
		procFSWalkSensorName,
	)

	ProcFSConfigKprobe = program.MapBuilder(procFSConfigMapName, ProcFSWalkKprobe)
	ProcFSConfigFentry = program.MapBuilder(procFSConfigMapName, ProcFSWalkFentry)
)

func init() {
	loader := &loader{}
	sensors.RegisterProbeType(procFSWalkSensorName, loader)
}

func GetPrograms() (progs []*program.Program) {
	if !utils.SupportProcessTree() {
		return
	}
	if utils.SupportFentry() {
		progs = append(progs, ProcFSWalkFentry)
	} else {
		progs = append(progs, ProcFSWalkKprobe)
	}
	return progs
}

func GetMaps() (maps []*program.Map) {
	if !utils.SupportProcessTree() {
		return
	}
	if utils.SupportFentry() {
		maps = append(maps, ProcFSConfigFentry)
	} else {
		maps = append(maps, ProcFSConfigKprobe)
	}
	return maps
}

type loader struct{}

func (loader *loader) LoadProbe(args sensors.LoadProbeArgs) error {
	switch args.Load.Attach {
	case "fentry":
		return program.LoadTracingProgram(args.BPFDir, args.Load, args.Maps, args.Verbose)
	default:
		return program.LoadKprobeProgram(args.BPFDir, args.Load, args.Maps, args.Verbose)
	}
}

func LoadInitialSensor(ctx context.Context) error {
	mgr := observer.GetSensorManager()
	initialProcFSSensor := &sensors.Sensor{
		Name:  procFSWalkSensorName,
		Progs: GetPrograms(),
		Maps:  GetMaps(),
	}
	if err := mgr.AddSensor(ctx, initialProcFSSensor.Name, initialProcFSSensor); err != nil {
		return err
	}
	return mgr.EnableSensor(ctx, initialProcFSSensor.Name)
}

func openConfigMap() (*ebpf.Map, error) {
	mapDir := bpf.MapPrefixPath()

	var configMapPath string
	if utils.SupportFentry() {
		configMapPath = filepath.Join(mapDir, ProcFSConfigFentry.PinPath)
	} else {
		configMapPath = filepath.Join(mapDir, ProcFSConfigKprobe.PinPath)
	}

	m, err := ebpf.LoadPinnedMap(configMapPath, nil)
	for i := 0; err != nil; i++ {
		m, err = ebpf.LoadPinnedMap(configMapPath, nil)
		if err != nil {
			time.Sleep(mapRetryDelay * time.Second)
		}
		if i > maxMapRetries {
			return nil, fmt.Errorf("unable to access procfs config map: %w", err)
		}
	}
	return m, nil
}

func ProcFSWalk() error {
	access.Lock()
	defer access.Unlock()

	m, err := openConfigMap()
	if err != nil {
		return fmt.Errorf("failed to open procfs lookup config map: %w", err)
	}
	defer m.Close()

	procFS, err := os.ReadDir(option.Config.ProcFS)
	if err != nil {
		logger.GetLogger().WithError(err).Errorf("Could not read directory %s", option.Config.ProcFS)
		return err
	}

	k := &modelapi.ProcFSConfigKey{Zero: 0}
	v := &modelapi.ProcFSConfigValue{
		SignalHit: 0,
		Enabled:   1,
	}
	m.Put(k, v)

	numIterations := 10
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
			fmt.Printf("failed to read pid err=%s\n", err)
			logger.GetLogger().WithError(err).Debugf("pid read error")
			continue
		}

		for range numIterations {
			os.ReadFile(filepath.Join(option.Config.ProcFS, fmt.Sprintf("%d", pid), "comm"))
			err := m.Lookup(k, v)
			if err == nil && v.SignalHit == 1 {
				break
			}
			// Need a little wait to allow the probe to be attached (only
			// applies to first iteration of outer loop).
			time.Sleep(10 & time.Millisecond)
		}
	}

	v.Enabled = 0
	v.SignalHit = 0
	m.Put(k, v)

	return nil
}
