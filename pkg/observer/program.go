//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//
package observer

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"syscall"

	"github.com/isovalent/hubble-fgs/pkg/bpf"
	"github.com/isovalent/hubble-fgs/pkg/btf"
	"github.com/isovalent/hubble-fgs/pkg/config"
	"github.com/isovalent/hubble-fgs/pkg/kernels"
	"github.com/isovalent/hubble-fgs/pkg/logger"
	"github.com/vishvananda/netlink"

	"golang.org/x/sys/unix"
)

var (
	ObserverExecve = BpfLoad{
		"bpf_execve_event.o",
		"sched/sched_process_exec",
		"sched/sched_process_exec",
		"tracepoint/sys_execve",
		"event_execve",

		false,
		true,
		"tracepoint",
		bpfLoadStateIdle(),

		-1,

		struct{}{},
	}

	ObserverExit = BpfLoad{
		"bpf_exit.o",
		"sched/sched_process_exit",
		"sched/sched_process_exit",
		"tracepoint/sys_exit",
		"event_exit",

		false,
		true,
		"tracepoint",
		bpfLoadStateIdle(),

		-1,

		struct{}{},
	}

	ObserverFork = BpfLoad{
		"bpf_fork.o",
		"wake_up_new_task",
		"wake_up_new_task",
		"kprobe/wake_up_new_task",
		"kprobe_pid_clear",

		false,
		true,
		"kprobe",
		bpfLoadStateIdle(),

		-1,

		struct{}{},
	}

	ObserverCred = BpfLoad{
		"bpf_cred.o",
		"commit_creds",
		"commit_creds",
		"kprobe/commit_creds",
		"kprobe_commit_creds",

		false,
		true,
		"kprobe",
		bpfLoadStateIdle(),

		-1,

		struct{}{},
	}

	ObserverTCPConnect = BpfLoad{
		"bpf_tcpmon.o",
		"tcp_connect",
		"tcp_connect",
		"kprobe/tcp_connect",
		"kprobe_tcp_connect",

		false,
		true,
		"kprobe",
		bpfLoadStateIdle(),

		-1,

		struct{}{},
	}

	ObserverTCPConnectRet = BpfLoad{
		"bpf_tcpmonret.o",
		"__x64_sys_connect",
		"sys_connect",
		"kretprobe/sys_connect",
		"kretprobe_sys_connect",

		true,
		true,
		"kprobe",
		bpfLoadStateIdle(),

		-1,

		struct{}{},
	}

	ObserverTCPClose = BpfLoad{
		"bpf_tcpclose.o",
		"tcp_set_state",
		"tcp_set_state",
		"kprobe/tcp_set_state",
		"kprobe_tcp_set_state",

		false,
		true,
		"kprobe",
		bpfLoadStateIdle(),

		-1,

		struct{}{},
	}

	ObserverTCPSendCheck = BpfLoad{
		"bpf_tcp_send_check.o",
		"tcp_v4_send_check",
		"tcp_v4_send_check",
		"kprobe/tcp_v4_send_check",
		"kprobe_tcp_v4_send_check",

		false,
		true,
		"kprobe",
		bpfLoadStateIdle(),

		-1,

		struct{}{},
	}

	ObserverListen = BpfLoad{
		"bpf_listen.o",
		"__inet_hash",
		"__inet_hash",
		"kprobe/inet_hash",
		"kprobe_inet_hash",

		false,
		true,
		"kprobe",
		bpfLoadStateIdle(),

		-1,

		struct{}{},
	}

	observerAllPrograms = []*BpfLoad{
		&ObserverExecve,
		&ObserverExit,
		&ObserverFork,
		&ObserverCred,
		&ObserverTCPConnect,
		&ObserverTCPConnectRet,
		&ObserverTCPClose,
		&ObserverTCPSendCheck,
		&ObserverListen,
	}

	/* Event Ring map */
	ObserverTCPMonMap = ObserverMap{"tcpmon_map", "", &ObserverExecve, bpfLoadStateIdle(), -1}
	/* Networking and Process Monitoring maps */
	ObserverExecveMap           = ObserverMap{"execve_map", "", &ObserverExecve, bpfLoadStateIdle(), -1}
	ObserverSocketMap           = ObserverMap{"socket_map", "", &ObserverTCPConnect, bpfLoadStateIdle(), -1}
	ObserverTcpMap              = ObserverMap{"ipv4_tcp_map", "", &ObserverTCPConnect, bpfLoadStateIdle(), -1} // NB: This seems to be unused?
	ObserverTcpSendCheckSampler = ObserverMap{"tcp_send_check_sampler", "", &ObserverTCPSendCheck, bpfLoadStateIdle(), -1}
	/* Internal statistics for debugging */
	ObserverExecveStats = ObserverMap{"execve_map_stats", "", &ObserverExecve, bpfLoadStateIdle(), -1}
	ObserverSocketStats = ObserverMap{"socket_map_stats", "", &ObserverExecve, bpfLoadStateIdle(), -1}
	ObserverTlsStats    = ObserverMap{"tls_map_stats", "", &ObserverExecve, bpfLoadStateIdle(), -1}
	/* Cilium maps */
	ObserverCiliumSnat = ObserverMap{"cilium_snat_v4_external", "", &ObserverTCPConnect, bpfLoadStateIdle(), -1}

	observerAllMaps = []*ObserverMap{
		&ObserverSocketMap,
		&ObserverExecveMap,
		&ObserverTCPMonMap,
		&ObserverExecveStats,
		&ObserverSocketStats,
		&ObserverTlsStats,
		&ObserverCiliumSnat,
		&ObserverTcpSendCheckSampler,
	}
)

// bpfLoadState represents the state of a BPF program or map
//
// NB: Currently there is no case where we attempt to load a program that is
// already loaded. If this changes, we can use the count as a reference count
// to track users of a bpf program.
type bpfLoadState struct {
	//   0: idle (not loaded)
	//   1: loaded
	//  -1: disabled
	count int
}

func bpfLoadStateIdle() bpfLoadState {
	return bpfLoadState{0}
}

func (s *bpfLoadState) isLoaded() bool {
	return s.count > 0
}

func (s *bpfLoadState) isIdle() bool {
	return s.count == 0
}

func (s bpfLoadState) isDisabled() bool {
	return s.count == -1
}

func (s *bpfLoadState) setDisabled() {
	if s.isLoaded() {
		panic(fmt.Errorf("called setDisabled() while program is loaded (cnt: %d)", s.count))
	}
	s.count = -1
}

func (s *bpfLoadState) setLoaded() {
	if s.isDisabled() {
		panic(fmt.Errorf("called setLoaded() while program is disabled (cnt: %d)", s.count))
	}
	s.count = 1
}

type BpfLoad struct {
	Observer__program    string
	observer__x64_attach string
	observer__attach     string
	observer__label      string
	observer__prog       string

	retProbe   bool
	errorFatal bool

	probeType string
	loadState bpfLoadState

	tracefd int

	loaderData interface{}
}

func BpfLoadBuilder(program, x64_attach, attach, label, prog string,
	ret, errFatal bool,
	ty string) *BpfLoad {
	return &BpfLoad{
		program, x64_attach, attach, label, prog, ret, errFatal, ty,
		bpfLoadStateIdle(), -1, struct{}{},
	}
}

func GetBpfLoad(l *BpfLoad) (program, label, prog string) {
	return l.Observer__program, l.observer__label, l.observer__prog
}

func BpfMapBuilder(name, ty string, ld *BpfLoad) *ObserverMap {
	return &ObserverMap{name, ty, ld, bpfLoadStateIdle(), -1}
}

func SensorBuilder(name string, p []*BpfLoad, m []*ObserverMap) *ObserverSensor {
	return &ObserverSensor{
		name:  name,
		progs: p,
		maps:  m,
	}
}

// createInitialObserverSensor retruns the ObserverSensor that is loaded at initialization time
func createInitialObserverSensor() *ObserverSensor {
	progs := []*BpfLoad{
		&ObserverExecve,
		&ObserverExit,
		&ObserverFork,
		&ObserverCred,
		&ObserverTCPConnect,
		&ObserverTCPConnectRet,
		&ObserverTCPClose,
		&ObserverTCPSendCheck,
		&ObserverListen,
	}

	maps := []*ObserverMap{
		&ObserverTCPMonMap,
		&ObserverExecveMap,
		&ObserverSocketMap,
		/* &ObserverTcpMap */
		&ObserverExecveStats,
		&ObserverSocketStats,
		&ObserverTlsStats, // NB: Maybe this should be under k.enableTLS?
		&ObserverTcpSendCheckSampler,
	}

	return &ObserverSensor{
		name:  "__main__",
		progs: progs,
		maps:  maps,
	}
}

func removeProgram(bpfDir string, prog *BpfLoad) {
	os.Remove(bpfDir + prog.observer__prog)
	if prog.probeType == "generic_kprobe" {
		coreFile := ""
		splitProg := strings.Split(prog.observer__prog, "__")
		if (len(splitProg)) > 1 {
			coreFile = splitProg[1]
		} else {
			splitProg = strings.Split(prog.observer__prog, "kprobe_")
			if len(splitProg) < 2 {
				splitProg = strings.Split(prog.observer__prog, "kretprobe_")
			}
			coreFile = splitProg[1]
		}
		fmt.Printf("remove strings %s\n", coreFile)
		files, err := ioutil.ReadDir(bpfDir)
		if err == nil {
			for _, f := range files {
				if strings.Contains(f.Name(), coreFile) {
					if f.IsDir() {
						os.RemoveAll(bpfDir + f.Name())
					} else {
						os.Remove(bpfDir + f.Name())
					}
				}
			}
		}
		os.Remove(bpfDir + prog.observer__prog + "-kp-calls")
	}
	if prog.tracefd >= 0 {
		removeTracepoint(prog.tracefd)
		prog.tracefd = -1
	}
}

func RemovePrograms(bpfDir, mapDir string) {
	for _, l := range observerAllPrograms {
		removeProgram(bpfDir, l)
	}

	for _, m := range observerAllMaps {
		if m.fd > 0 {
			syscall.Close(m.fd)
		}
		os.Remove(mapDir + m.mapName)
	}
	os.Remove(bpfDir)
	os.Remove(mapDir)
	btf.FreeCachedBTF()
}

func disableBpfLoad(bpf *BpfLoad) {
	bpf.loadState.setDisabled()
	for _, om := range observerAllMaps {
		if om.bpf == bpf {
			logger.GetLogger().Infof("disabling map %s", om.mapName)
			om.pinState.setDisabled()
		}
	}
}

func observerFindProgs(ctx context.Context, sensor *ObserverSensor) error {
	for _, p := range sensor.progs {
		if _, err := os.Stat(p.Observer__program); err == nil {
			continue
		}
		logger.GetLogger().WithField("file", p.Observer__program).Info("candidate bpf file does not exist")
		last := strings.Split(p.Observer__program, "/")
		filename := last[len(last)-1]

		path := path.Join(HubbleLib, filename)
		if _, err := os.Stat(path); err == nil {
			p.Observer__program = path
			continue
		}
		logger.GetLogger().WithField("file", path).Info("candidate bpf file does not exist")

		if IgnoreMissingProgs {
			logger.GetLogger().Warningf("failed to find BPF prog %s, but was told to ignore such errors. Disabling it and moving on.", p.Observer__program)
			disableBpfLoad(p)
			continue
		}

		return fmt.Errorf("Observer Program '%s' can not be found\n", p.Observer__program)
	}
	return nil
}

func observerLoadSensorMaps(stopCtx context.Context, sensor *ObserverSensor, mapDir string) error {
	version, _, err := kernels.GetKernelVersion(KernelVersion, ProcFS)
	if err != nil {
		return err
	}

	for _, m := range sensor.maps {
		var err error

		if m.pinState.isDisabled() {
			logger.GetLogger().Infof("hubble-fgs, map %s is disabled, skipping.\n", m.mapName)
			continue
		}

		pin := mapDir + m.mapName
		btfObj := uintptr(btf.GetCachedBTF())
		m.fd, err = bpf.LoadAndPinMaps(version, Verbosity, btfObj, m.bpf.Observer__program, pin, m.mapName,
			NameToProgType(m.bpf.probeType))
		logger.GetLogger().Debugf("LoadAndPinMaps(%s, %s, %s)\n", m.bpf.Observer__program, pin, m.mapName)
		if err != nil {
			return fmt.Errorf("failed %d load map (%s): %s\n", m.fd, m.mapType, err)
		}
		logger.GetLogger().Infof("hubble-fgs, map %s was loaded at %s.\n", m.mapName, pin)
	}

	return nil
}

func getDefaultRouteLinks() ([]netlink.Link, error) {
	var links []netlink.Link

	nilDst := &netlink.Route{Dst: nil}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, nilDst, netlink.RT_FILTER_DST)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("RouteListFiltered failed:")
		return nil, err
	}
	allLinks, err := netlink.LinkList()
	if err != nil {
		logger.GetLogger().WithError(err).Warn("LinkList failed:")
		return nil, err
	}
	for _, route := range routes {
		for _, link := range allLinks {
			if link.Attrs().Index == route.LinkIndex {
				links = append(links, link)
			}
		}
	}
	return links, nil
}

func ObserverLoadSkmsg(
	bpfDir, mapDir, ciliumDir string,
	load *BpfLoad,
	version, verbose int, x64 bool) (error, int) {
	btfObj := uintptr(btf.GetCachedBTF())

	return bpf.LoadSkmsgProgram(
		version, Verbosity,
		btfObj,
		load.Observer__program,
		load.observer__label,
		bpfDir+load.observer__prog,
		mapDir)
}

func ObserverLoadSkSkbVerdict(
	bpfDir, mapDir, ciliumDir string,
	load *BpfLoad,
	version, verbose int, x64 bool) (error, int) {
	btfObj := uintptr(btf.GetCachedBTF())

	return bpf.LoadSkSkbVerdictProgram(
		version, Verbosity,
		btfObj,
		load.Observer__program,
		load.observer__label,
		bpfDir+load.observer__prog,
		mapDir)
}

func ObserverLoadSkSkb(
	bpfDir, mapDir, ciliumDir string,
	load *BpfLoad,
	version, verbose int, x64 bool) (error, int) {
	btfObj := uintptr(btf.GetCachedBTF())

	return bpf.LoadSkSkbParserProgram(
		version, Verbosity,
		btfObj,
		load.Observer__program,
		load.observer__label,
		bpfDir+load.observer__prog,
		mapDir)
}

func ObserverLoadSockops(
	bpfDir, mapDir, ciliumDir string,
	load *BpfLoad,
	version, verbose int, x64 bool) (error, int) {
	btfObj := uintptr(btf.GetCachedBTF())

	return bpf.LoadSockopsProgram(version, Verbosity, btfObj,
		load.Observer__program,
		load.observer__label,
		bpfDir+load.observer__prog,
		mapDir)
}

func ObserverLoadTC(bpfDir, mapDir, ciliumDir string, load *BpfLoad, version, Verbosity int) (error, int) {
	var attachLinks []netlink.Link

	btfObj := uintptr(btf.GetCachedBTF())
	err, fd := bpf.LoadTC(version, Verbosity,
		btfObj,
		load.Observer__program,
		load.observer__label,
		bpfDir+load.observer__prog,
		mapDir,
		ciliumDir)
	if err != nil {
		return err, fd
	}
	attachLinks, err = getDefaultRouteLinks()
	if err != nil {
		return err, 0
	}

	for _, link := range attachLinks {
		logger.GetLogger().Infof("Attaching %s to device %s", load.probeType, link.Attrs().Name)
		isIngress := "tc_ingress" == load.probeType
		if err = bpf.QdiscTCInsert(link.Attrs().Name, isIngress); err != nil {
			return err, 0
		}
		bpf.AttachTCIngress(fd, link.Attrs().Name, isIngress)
	}

	return nil, 0
}

func loadInstance(bpfDir, mapDir, ciliumDir string, load *BpfLoad, version, Verbosity int, x64 bool) (error, int) {
	var attach string

	if x64 {
		attach = load.observer__x64_attach
	} else {
		attach = load.observer__attach
	}
	btfObj := uintptr(btf.GetCachedBTF())
	if load.probeType == "tracepoint" {
		return bpf.LoadTracingProgram(
			version, Verbosity,
			btfObj,
			load.Observer__program,
			attach,
			load.observer__label,
			bpfDir+load.observer__prog,
			mapDir)
	} else if load.probeType == "cgrp_ingress" {
		return bpf.LoadCgroupProgram(
			version, Verbosity,
			btfObj,
			load.Observer__program,
			load.observer__label,
			bpfDir+load.observer__prog,
			mapDir)
	} else {
		if s, ok := registeredProbeLoad[load.probeType]; ok {
			return s.LoadProbe(bpfDir, mapDir, ciliumDir, load, version, Verbosity, x64)
		}
		return bpf.LoadKprobeProgram(
			version, Verbosity,
			btfObj,
			load.Observer__program,
			attach,
			load.observer__label,
			bpfDir+load.observer__prog,
			mapDir,
			load.retProbe)
	}
}

func observerLoadInstance(bpfDir, mapDir, ciliumDir string, load *BpfLoad, stopCtx context.Context) error {
	var fd int

	version, _, err := kernels.GetKernelVersion(KernelVersion, ProcFS)
	if err != nil {
		return err
	}

	logger.GetLogger().Debugf("prog %s kern_version %d\n", load.Observer__program, version)
	if load.probeType == "tracepoint" {
		err, fd = loadInstance(bpfDir, mapDir, ciliumDir, load, version, Verbosity, true)
		if err != nil && fd == -17 { // tracepoint exists be unfriendly and delete it
			logger.GetLogger().Infof("Tracepoint %s exists: removing and retrying", load.Observer__program)
			removeTracepoint(load.tracefd)
			err, fd = loadInstance(bpfDir, mapDir, ciliumDir, load, version, Verbosity, true)
		}
		if err != nil {
			return fmt.Errorf("Failed prog %s kern_version %d err %d LoadTracingProgram: %s\n",
				load.Observer__program, version, fd, err)
		}
	} else {
		err, fd = loadInstance(bpfDir, mapDir, ciliumDir, load, version, Verbosity, true)
		if err != nil {
			/* If we fail attach with __x64_sys_execve variant try again with
			 * sys_execve variant.
			 */
			err, fd = loadInstance(bpfDir, mapDir, ciliumDir, load, version, Verbosity, false)
			if err != nil && load.errorFatal {
				return fmt.Errorf("Failed prog %s kern_version %d LoadKprobeProgram: %s\n",
					load.Observer__program, version, err)
			}
		}
	}
	load.tracefd = fd
	return nil
}

func observerUnloadSensor(bpfDir, mapDir string, sensor *ObserverSensor, ctx context.Context) error {
	logger.GetLogger().Infof("Unloading sensor %s", sensor.name)
	if !sensor.loaded {
		logger.GetLogger().Warningf("attempted to unload sensor %s which is not loaded", sensor.name)
		return fmt.Errorf("unload of sensor %s failed: sensor not loaded", sensor.name)
	}

	for _, p := range sensor.progs {
		removeProgram(bpfDir, p)
	}

	for _, m := range sensor.maps {
		os.Remove(mapDir + m.mapName)
	}

	sensor.loaded = false
	return nil
}

func ObserverLoadSensor(bpfDir, mapDir, ciliumDir string, stopCtx context.Context, sensor *ObserverSensor) error {
	if sensor == nil {
		return nil
	}

	logger.GetLogger().Infof("Loading sensor %s", sensor.name)
	if sensor.loaded {
		logger.GetLogger().Warningf("attempted to load sensor %s which is already loaded", sensor.name)
		return fmt.Errorf("loading sensor %s failed: sensor already loaded", sensor.name)
	}

	_, verStr, _ := kernels.GetKernelVersion(KernelVersion, ProcFS)
	logger.GetLogger().Infof("Loading kernel version %s", verStr)

	if err := observerFindProgs(stopCtx, sensor); err != nil {
		return fmt.Errorf("hubble-fgs, Aborting could not find BPF programs. %s\n", err)
	}
	if err := observerLoadSensorMaps(stopCtx, sensor, mapDir); err != nil {
		return err
	}

	for _, p := range sensor.progs {
		if p.loadState.isDisabled() {
			logger.GetLogger().Infof("hubble-fgs, prog %s is disabled, skipping.\n", p.Observer__program)
			continue
		}

		if err := observerLoadInstance(bpfDir, mapDir, ciliumDir, p, stopCtx); err != nil {
			return err
		}
		p.loadState.setLoaded()
		logger.GetLogger().Infof("hubble-fgs, prog %s was loaded.\n", p.Observer__program)
	}
	logger.GetLogger().Infof("hubble-fgs, loaded BPF maps and events for sensor %s successfully.\n", sensor.name)
	sensor.loaded = true
	return nil
}

func removeTracepoint(fd int) {
	PERF_EVENT_IOC_DISABLE := uint(0x2401)
	err := unix.IoctlSetInt(fd, PERF_EVENT_IOC_DISABLE, 0)
	if err != nil && Verbosity > 1 {
		logger.GetLogger().WithError(err).Warnf("Warning failed tracepoint removal")
	}
	unix.Close(fd)
}

func observerMinReqs(ctx context.Context) (bool, error) {
	_, _, err := kernels.GetKernelVersion(KernelVersion, ProcFS)
	if err != nil {
		return false, fmt.Errorf("Kernel version lookup failed, required for kprobe.\n")
	}
	return true, nil
}

func createDir(bpfDir, mapDir string) {
	os.Mkdir(bpfDir, os.ModeDir)
	os.Mkdir(mapDir, os.ModeDir)
}

func createConfigSensors(configFile string) ([]*ObserverSensor, error) {
	var sensors []*ObserverSensor

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

func mergeSensors(sensors []*ObserverSensor) *ObserverSensor {
	var progs []*BpfLoad
	var maps []*ObserverMap

	for _, s := range sensors {
		progs = append(progs, s.progs...)
		maps = append(maps, s.maps...)
	}
	return &ObserverSensor{
		name:  "__main__",
		progs: progs,
		maps:  maps,
	}
}

func LoadDefaultSensor(bpfDir, mapDir, ciliumDir, configFile string, ctx context.Context) error {
	createDir(bpfDir, mapDir)

	logger.GetLogger().WithField("metadata", ObserverBTF).Info("Using metadata file")
	if _, err := observerMinReqs(ctx); err != nil {
		return fmt.Errorf("hubble-fgs, Aborting minimum requirements not met. %s\n", err)
	}

	// This is technically not a sensor since we are loading this
	// statically when we start, but it allows us to have a single path for
	// loading bpf programs.
	initialSensors := createInitialObserverSensor()
	configSensors, err := createConfigSensors(configFile)
	if err != nil {
		return err
	}
	sensors := append([]*ObserverSensor{initialSensors}, configSensors...)
	load := mergeSensors(sensors)
	// Add config file loaded programs and maps to observerAll* so unload will
	// cleanup these as well as default programs/maps.
	for _, s := range configSensors {
		observerAllPrograms = append(observerAllPrograms, s.progs...)
		observerAllMaps = append(observerAllMaps, s.maps...)
	}

	if err := ObserverLoadSensor(bpfDir, mapDir, ciliumDir, ctx, load); err != nil {
		return fmt.Errorf("hubble-fgs, Aborting could not load BPF programs. %s\n", err)
	}

	return nil
}
