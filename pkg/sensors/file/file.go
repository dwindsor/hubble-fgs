//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package file

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/isovalent/hubble-fgs/pkg/api/fileapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/isovalent/hubble-fgs/pkg/observer"
)

const (
	filterIgnore = 0
	filterMatch  = 1
)

type observerFileSensor struct {
	name string
}

func init() {
	file := &observerFileSensor{
		name: "file sensor",
	}
	sensors.RegisterProbeType("file_monitoring", file)
	sensors.RegisterTracingSensorsAtInit(file.name, file)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_FILE, handleFileOps)
}

func handleFileOps(r *bytes.Reader) ([]observer.Event, error) {
	m := fileapi.MsgFileEvent{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		return nil, fmt.Errorf("Failed to read file operation: %w", err)
	}

	str := string(m.Path.Str[:m.Path.Size])
	unix := &fileapi.MsgFileEventUnix{
		Common:     m.Common,
		ProcessKey: m.ProcessKey,
		Path:       str,
		Action:     m.Action,
		Hook:       m.Hook,
		Timestamp:  m.Timestamp,
		Ino:        m.Ino,
	}

	return []observer.Event{unix}, nil
}

type LocalMap struct {
	Name      string
	Prog      *program.Program
	PinState  program.State
	MapHandle *ebpf.Map
}

type LPMMapKey struct {
	Prefixlen uint32
	Data      [256]byte
}

type LPMMapValue uint32

func addFilter(handle *ebpf.Map, filter string, val LPMMapValue) error {
	var k LPMMapKey

	k.Prefixlen = uint32(len(filter)) * 8
	copy(k.Data[:], filter)

	err := handle.Update(k, val, ebpf.UpdateAny)
	if err != nil {
		return fmt.Errorf("failed handle.Update: %w", err)
	}
	return nil
}

func addFileMonitoringSensor(kprobes v1alpha1.FileSpec, btfBaseFile string) (*sensors.Sensor, error) {
	var progs []*program.Program
	var maps []*program.Map

	l := logger.GetLogger()
	mapDir := bpf.MapPrefixPath()
	os.Mkdir(mapDir, os.ModeDir)

	ms := &ebpf.MapSpec{
		Name:       "lpm_trie_map_alloc",
		Type:       bpf.BPF_MAP_TYPE_LPM_TRIE,
		KeySize:    4 + 256,
		ValueSize:  4,
		MaxEntries: 4096,
		Flags:      bpf.BPF_F_NO_PREALLOC,
		Pinning:    ebpf.PinByName,
	}

	mo := ebpf.MapOptions{
		PinPath:        mapDir,
		LoadPinOptions: ebpf.LoadPinOptions{},
	}

	handle, err := ebpf.NewMapWithOptions(ms, mo)
	if err != nil {
		return nil, fmt.Errorf("failed ebpf.NewMapWithOptions: %w", err)
	}

	for _, str := range kprobes.Paths {
		l.Warnf("WatchPath = %s", str)
		err := addFilter(handle, str, filterMatch)
		if err != nil {
			return nil, fmt.Errorf("failed to add WatchPath: %w", err)
		}
	}

	for _, str := range kprobes.PathsExclude {
		l.Warnf("ExcludePaths = %s", str)
		err := addFilter(handle, str, filterIgnore)
		if err != nil {
			return nil, fmt.Errorf("failed to add ExcludePath: %w", err)
		}
	}

	hooks := [...]string{
		"vfs_fallocate",
		"filemap_fault",
		"filemap_map_pages",
		"filemap_page_mkwrite",
		"rw_verify_area",
	}
	progName := "bpf_file.o"

	for idx, h := range hooks {
		load := program.Builder(
			path.Join(option.Config.HubbleLib, progName),
			h,
			"kprobe/"+h,
			fmt.Sprintf("file_ops_%s", h),
			"kprobe").
			SetLoaderData(idx)
		load.Override = false
		progs = append(progs, load)
		mp := program.MapBuilder(
			"lpm_trie_map_alloc",
			load,
		)
		(*LocalMap)(unsafe.Pointer(&mp)).MapHandle = handle // FIXME: mp.SetMapHandle(handle)
		maps = append(maps, mp)
	}

	return &sensors.Sensor{
		Name:  "file_monitoring_sensor",
		Progs: progs,
		Maps:  maps,
	}, nil
}

func (k *observerFileSensor) SpecHandler(raw interface{}) (*sensors.Sensor, error) {
	spec := raw.(*v1alpha1.TracingPolicySpec)
	if len(spec.FileMonitoring.Paths) == 0 && len(spec.FileMonitoring.PathsExclude) > 0 {
		return nil, fmt.Errorf("FileMonitoring requires more that one file_paths when file_paths_exclude is defined")
	}
	if len(spec.FileMonitoring.Paths) > 0 {
		if !kernels.MinKernelVersion("5.4.0") {
			return nil, fmt.Errorf("FileMonitoring requires at least 5.4.0 version")
		}
		logger.GetLogger().Warnf("FileMonitoring is enabled with %d paths to watch and %d exclude paths!", len(spec.FileMonitoring.Paths), len(spec.FileMonitoring.PathsExclude))
		return addFileMonitoringSensor(spec.FileMonitoring, option.Config.BTF)
	}
	return nil, nil
}

func (k *observerFileSensor) LoadProbe(args sensors.LoadProbeArgs) (int, error) {
	// all is done in SpecHandler
	return 0, nil
}
