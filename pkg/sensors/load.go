//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package sensors

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	loader "github.com/isovalent/hubble-fgs/pkg/bpf"
	"github.com/isovalent/hubble-fgs/pkg/btf"
	"github.com/isovalent/hubble-fgs/pkg/config"
	"github.com/isovalent/hubble-fgs/pkg/kernels"
	"github.com/isovalent/hubble-fgs/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/option"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const (
	BPF_PROG_TYPE_UNSPEC                  = 0
	BPF_PROG_TYPE_SOCKET_FILTER           = 1
	BPF_PROG_TYPE_KPROBE                  = 2
	BPF_PROG_TYPE_SCHED_CLS               = 3
	BPF_PROG_TYPE_SCHED_ACT               = 4
	BPF_PROG_TYPE_TRACEPOINT              = 5
	BPF_PROG_TYPE_XDP                     = 6
	BPF_PROG_TYPE_PERF_EVENT              = 7
	BPF_PROG_TYPE_CGROUP_SKB              = 8
	BPF_PROG_TYPE_CGROUP_SOCK             = 9
	BPF_PROG_TYPE_LWT_IN                  = 10
	BPF_PROG_TYPE_LWT_OUT                 = 11
	BPF_PROG_TYPE_LWT_XMIT                = 12
	BPF_PROG_TYPE_SOCK_OPS                = 13
	BPF_PROG_TYPE_SK_SKB                  = 14
	BPF_PROG_TYPE_CGROUP_DEVICE           = 15
	BPF_PROG_TYPE_SK_MSG                  = 16
	BPF_PROG_TYPE_RAW_TRACEPOINT          = 17
	BPF_PROG_TYPE_CGROUP_SOCK_ADDR        = 18
	BPF_PROG_TYPE_LWT_SEG6LOCAL           = 19
	BPF_PROG_TYPE_LIRC_MODE2              = 20
	BPF_PROG_TYPE_SK_REUSEPORT            = 21
	BPF_PROG_TYPE_FLOW_DISSECTOR          = 22
	BPF_PROG_TYPE_CGROUP_SYSCTL           = 23
	BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE = 24
	BPF_PROG_TYPE_CGROUP_SOCKOPT          = 25
	BPF_PROG_TYPE_TRACING                 = 26
	BPF_PROG_TYPE_STRUCT_OPS              = 27
	BPF_PROG_TYPE_EXT                     = 28
	BPF_PROG_TYPE_LSM                     = 29
)

// LoadDefault loads the default sensor, including any from the configuration
// file.
func LoadDefault(bpfDir, mapDir, ciliumDir, configFile string, ctx context.Context) error {
	createDir(bpfDir, mapDir)

	logger.GetLogger().WithField("metadata", option.Config.BTF).Info("Using metadata file")
	if _, err := observerMinReqs(ctx); err != nil {
		return fmt.Errorf("hubble-fgs, aborting minimum requirements not met: %w", err)
	}

	// This is technically not a sensor since we are loading this
	// statically when we start, but it allows us to have a single path for
	// loading bpf programs.
	initialSensors := GetInitialSensor()
	configSensors, err := createConfigSensors(configFile)
	if err != nil {
		return err
	}
	sensors := append([]*Sensor{initialSensors}, configSensors...)
	load := mergeSensors(sensors)
	// Add config file loaded programs and maps to All* so unload will cleanup
	// these as well as default programs/maps.
	for _, s := range configSensors {
		AllPrograms = append(AllPrograms, s.Progs...)
		AllMaps = append(AllMaps, s.Maps...)
	}

	if err := load.Load(ctx, bpfDir, mapDir, ciliumDir); err != nil {
		return fmt.Errorf("hubble-fgs, aborting could not load BPF programs: %w", err)
	}

	return nil
}

// Load loads the sensor, by loading all the BPF programs and maps.
func (s *Sensor) Load(stopCtx context.Context, bpfDir, mapDir, ciliumDir string) error {
	if s == nil {
		return nil
	}

	l := logger.GetLogger()

	l.WithField("name", s.Name).Info("Loading sensor")
	if s.Loaded {
		return fmt.Errorf("loading sensor %s failed: sensor already loaded", s.Name)
	}

	_, verStr, _ := kernels.GetKernelVersion(option.Config.KernelVersion, option.Config.ProcFS)
	l.Infof("Loading kernel version %s", verStr)

	if err := s.FindPrograms(stopCtx); err != nil {
		return fmt.Errorf("hubble-fgs, aborting could not find BPF programs: %w", err)
	}
	if err := s.LoadMaps(stopCtx, mapDir); err != nil {
		return fmt.Errorf("hubble-fgs, aborting could not load sensor BPF maps: %w", err)
	}

	for _, p := range s.Progs {
		if p.LoadState.IsDisabled() {
			l.WithField("prog", p.Name).Info("BPF prog is disabled, skipping")
			continue
		}

		if err := observerLoadInstance(bpfDir, mapDir, ciliumDir, p, stopCtx); err != nil {
			return err
		}

		p.LoadState.SetLoaded()
		l.WithField("prog", p.Name).Info("BPF prog was loaded")
	}
	l.WithField("sensor", s.Name).Infof("Loaded BPF maps and events for sensor successfully")
	s.Loaded = true
	return nil
}

func (s *Sensor) findProgram(p *Program) error {
	if _, err := os.Stat(p.Name); err == nil {
		return nil
	}
	logger.GetLogger().WithField("file", p.Name).Info("Candidate bpf file does not exist")
	last := strings.Split(p.Name, "/")
	filename := last[len(last)-1]

	path := path.Join(option.Config.HubbleLib, filename)
	if _, err := os.Stat(path); err == nil {
		p.Name = path
		return nil
	}
	logger.GetLogger().WithField("file", path).Info("Candidate bpf file does not exist")

	if option.Config.IgnoreMissingProgs {
		logger.GetLogger().Warningf("Failed to find BPF prog %s, but was told to ignore such errors. Disabling it and moving on.", p.Name)
		disableBpfLoad(p)
		return nil
	}

	return fmt.Errorf("sensor program %q can not be found", p.Name)
}

// FindPrograms finds all the BPF programs in the sensor on the filesytem.
func (s *Sensor) FindPrograms(ctx context.Context) error {
	for _, p := range s.Progs {
		if err := s.findProgram(p); err != nil {
			return err
		}
	}
	for _, m := range s.Maps {
		if err := s.findProgram(m.Prog); err != nil {
			return err
		}
	}
	return nil
}

// LoadMaps loads all the BPF maps in the sensor.
func (s *Sensor) LoadMaps(stopCtx context.Context, mapDir string) error {
	version, _, err := kernels.GetKernelVersion(option.Config.KernelVersion, option.Config.ProcFS)
	if err != nil {
		return err
	}

	l := logger.GetLogger()
	for _, m := range s.Maps {
		var err error

		if m.PinState.IsDisabled() {
			l.WithField("map", m.Name).Info("hubble-fgs, map is disabled, skipping.")
			continue
		}

		pin := filepath.Join(mapDir, m.Name)
		btfObj := uintptr(btf.GetCachedBTF())
		m.FD, err = loader.LoadAndPinMaps(version, option.Config.Verbosity, btfObj, m.Prog.Name, pin, m.Name, nameToProgType(m.Prog.Type))
		l.Debugf("LoadAndPinMaps(%s, %s, %s)", m.Prog.Name, pin, m.Name)
		if err != nil {
			return fmt.Errorf("failed %d load map (%s): %w", m.FD, m.Type, err)
		}
		l.WithFields(logrus.Fields{
			"map":  m.Name,
			"path": pin,
		}).Info("hubble-fgs, map loaded.")
	}

	return nil
}

func createConfigSensors(configFile string) ([]*Sensor, error) {
	var sensors []*Sensor

	if configFile == "" {
		return nil, nil
	}

	yamlData, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read yaml file %s: %w", configFile, err)
	}
	cnf, err := config.ReadConfigYaml(string(yamlData))
	if err != nil {
		return nil, err
	}
	for _, s := range registeredTracingSensors {
		sensor, err := s.SpecHandler(&cnf.Spec)
		if err != nil {
			return nil, err
		}
		if sensor == nil {
			continue
		}
		sensors = append(sensors, sensor)
	}
	return sensors, nil
}

func mergeSensors(sensors []*Sensor) *Sensor {
	var progs []*Program
	var maps []*Map

	for _, s := range sensors {
		progs = append(progs, s.Progs...)
		maps = append(maps, s.Maps...)
	}
	return &Sensor{
		Name:  "__main__",
		Progs: progs,
		Maps:  maps,
	}
}

func observerLoadInstance(bpfDir, mapDir, ciliumDir string, load *Program, stopCtx context.Context) error {
	var fd int

	version, _, err := kernels.GetKernelVersion(option.Config.KernelVersion, option.Config.ProcFS)
	if err != nil {
		return err
	}

	l := logger.GetLogger()
	l.WithFields(logrus.Fields{
		"prog":         load.Name,
		"kern_version": version,
	}).Debug("observerLoadInstance", load.Name, version)
	if load.Type == "tracepoint" {
		err, fd = loadInstance(bpfDir, mapDir, ciliumDir, load, version, option.Config.Verbosity, true)
		if err != nil && fd == -17 { // tracepoint exists be unfriendly and delete it
			l.WithField(
				"tracepoint", load.Name,
			).Info("Tracepoint exists: removing and retrying")
			removeTracepoint(load.TraceFD)
			err, fd = loadInstance(bpfDir, mapDir, ciliumDir, load, version, option.Config.Verbosity, true)
		}
		if err != nil {
			return fmt.Errorf("failed prog %s kern_version %d err %d LoadTracingProgram: %w",
				load.Name, version, fd, err)
		}
	} else {
		err, fd = loadInstance(bpfDir, mapDir, ciliumDir, load, version, option.Config.Verbosity, true)
		if err != nil {
			/* If we fail attach with __x64_sys_execve variant try again with
			 * sys_execve variant.
			 */
			err, fd = loadInstance(bpfDir, mapDir, ciliumDir, load, version, option.Config.Verbosity, false)
			if err != nil && load.ErrorFatal {
				return fmt.Errorf("failed prog %s kern_version %d LoadKprobeProgram: %w",
					load.Name, version, err)
			}
		}
	}
	load.TraceFD = fd
	return nil
}

func loadInstance(bpfDir, mapDir, ciliumDir string, load *Program, version, verbose int, x64 bool) (error, int) {
	var attach string

	if x64 {
		attach = load.X64Attach
	} else {
		attach = load.Attach
	}
	btfObj := uintptr(btf.GetCachedBTF())
	if load.Type == "tracepoint" {
		return loader.LoadTracingProgram(
			version, verbose,
			btfObj,
			load.Name,
			attach,
			load.Label,
			filepath.Join(bpfDir, load.PinPath),
			mapDir)
	} else if load.Type == "cgrp_socket" {
		return loader.LoadCgroupInetSocketProgram(
			version, verbose,
			btfObj,
			load.Name,
			load.Label,
			filepath.Join(bpfDir, load.PinPath),
			mapDir)
	} else {
		if s, ok := registeredProbeLoad[load.Type]; ok {
			return s.LoadProbe(LoadProbeArgs{
				BPFDir:    bpfDir,
				MapDir:    mapDir,
				CiliumDir: ciliumDir,
				Load:      load,
				Version:   version,
				Verbose:   verbose,
				X64:       x64,
			})
		}
		return loader.LoadKprobeProgram(
			version, verbose,
			btfObj,
			load.Name,
			attach,
			load.Label,
			filepath.Join(bpfDir, load.PinPath),
			mapDir,
			load.RetProbe)
	}
}

func observerMinReqs(ctx context.Context) (bool, error) {
	_, _, err := kernels.GetKernelVersion(option.Config.KernelVersion, option.Config.ProcFS)
	if err != nil {
		return false, fmt.Errorf("kernel version lookup failed, required for kprobe")
	}
	return true, nil
}

func createDir(bpfDir, mapDir string) {
	os.Mkdir(bpfDir, os.ModeDir)
	os.Mkdir(mapDir, os.ModeDir)
}

func disableBpfLoad(prog *Program) {
	prog.LoadState.SetDisabled()
	for _, om := range AllMaps {
		if om.Prog == prog {
			logger.GetLogger().WithField("map", om.Name).Infof("Disabling map")
			om.PinState.SetDisabled()
		}
	}
}

func removeTracepoint(fd int) {
	PERF_EVENT_IOC_DISABLE := uint(0x2401)
	err := unix.IoctlSetInt(fd, PERF_EVENT_IOC_DISABLE, 0)
	if err != nil && option.Config.Verbosity > 1 {
		logger.GetLogger().WithError(err).Warnf("Warning failed tracepoint removal")
	}
	unix.Close(fd)
}

func nameToProgType(n string) int {
	if strings.Contains(n, "skmsg") {
		n = "skmsg"
	}

	switch n {
	case "kprobe":
		return BPF_PROG_TYPE_KPROBE
	case "tracepoint":
		return BPF_PROG_TYPE_KPROBE
	case "sockops":
		return BPF_PROG_TYPE_SOCK_OPS
	case "skmsg":
		return BPF_PROG_TYPE_SK_MSG
	case "sk_skb_parser":
		return BPF_PROG_TYPE_SK_SKB
	case "sk_skb_verdict":
		return BPF_PROG_TYPE_SK_SKB
	case "cgrp_ingress",
		"cgrp_egress":
		return BPF_PROG_TYPE_CGROUP_SKB
	case "cgrp_socketopt",
		"cgrp_getsockopt":
		return BPF_PROG_TYPE_CGROUP_SOCKOPT
	case "tc_ingress":
		return BPF_PROG_TYPE_SCHED_CLS
	case "tc_egress":
		return BPF_PROG_TYPE_SCHED_CLS
	}
	return -1
}
