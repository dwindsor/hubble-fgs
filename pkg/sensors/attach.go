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
	"fmt"
	"os"
	"path/filepath"

	"github.com/isovalent/hubble-fgs/pkg/bpf"
	"github.com/isovalent/hubble-fgs/pkg/btf"
	"github.com/isovalent/hubble-fgs/pkg/logger"

	"github.com/vishvananda/netlink"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const (
	fgsCgroupPath = "/run/hubble-fgs/cgroup2"
)

type Selector struct {
	MapName   string
	Selectors [128]byte
}

func LoadSockOpt(
	bpfDir, mapDir, ciliumDir string,
	load *Program,
	version, verbose int,
	x64 bool,
	path string,
) (error, int) {
	return LoadCgroupProgram(bpfDir, mapDir, ciliumDir, load)
}

type WithProgramFunc func(*ebpf.Program, *ebpf.ProgramSpec) error

func rawAttachWithProgram(targetFD int) WithProgramFunc {
	return func(prog *ebpf.Program, spec *ebpf.ProgramSpec) error {
		err := link.RawAttachProgram(link.RawAttachProgramOptions{
			Target:  targetFD,
			Program: prog,
			Attach:  spec.AttachType,
		})
		if err != nil {
			if err := prog.Unpin(); err != nil {
				logger.GetLogger().WithError(err).Warn("Failed to unpin program after failed attach")
			}
			return fmt.Errorf("attaching '%s' failed: %w", spec.Name, err)
		}
		return nil
	}
}

func LoadSkProgram(
	bpfDir, mapDir string,
	load *Program,
	targetSockmap string,
) (error, int) {
	targetMap, err := ebpf.LoadPinnedMap(targetSockmap, nil)
	if err != nil {
		return fmt.Errorf("loading '%s' failed: %w", targetSockmap, err), 0
	}
	defer targetMap.Close()

	return loadProgram(bpfDir, []string{mapDir}, load,
		rawAttachWithProgram(targetMap.FD())), 0
}

// Sockops is different from other programs, in that it is shared across
// multiple sensors e.g. TLS and HTTP. So to ensure we only ever have one
// instance of the sockops lets guard the load by a refcnt check. We
// assume this is serialized by caller and it must be or else there would
// be interesting bugs when loaders and unloaders race.
func LoadSockops(
	bpfDir, mapDir, ciliumDir string,
	load *Program,
	version, verbose int,
	x64 bool) (error, int) {
	if bpf.IsSockopsLoaded() {
		logger.GetLogger().WithField("program", load.Name).Infof("Sockops, %d references exist reuse", bpf.SockopsRefCnt())
		return nil, 0
	}
	logger.GetLogger().WithField("program", load.Name).Infof("Sockops, create initial reference")
	bpf.CgroupSockopsRefInc()
	return LoadCgroupProgram(bpfDir, mapDir, ciliumDir, load)
}

func LoadTC(
	bpfDir, mapDir, ciliumDir string,
	load *Program,
	version, verbose int,
	selectors [128]byte,
) (error, int) {
	attach := func(prog *ebpf.Program, spec *ebpf.ProgramSpec) error {
		attachLinks, err := getDefaultRouteLinks()
		if err != nil {
			return err
		}

		for _, link := range attachLinks {
			logger.GetLogger().Infof("Attaching %s to device %s", load.Type, link.Attrs().Name)
			isIngress := "tc_ingress" == load.Type
			if err := bpf.QdiscTCInsert(link.Attrs().Name, isIngress); err != nil {
				return err
			}
			if err := bpf.AttachTCIngress(prog.FD(), link.Attrs().Name, isIngress); err != nil {
				return err
			}
		}
		return nil
	}
	err := loadProgram(bpfDir, []string{mapDir, ciliumDir}, load, attach)
	if err != nil {
		return err, 0
	}
	return nil, 0
}

func getDefaultRouteLinks() ([]netlink.Link, error) {
	var links []netlink.Link

	nilDst := &netlink.Route{Dst: nil}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, nilDst, netlink.RT_FILTER_DST)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("Failed to list selectored routes")
		return nil, err
	}
	allLinks, err := netlink.LinkList()
	if err != nil {
		logger.GetLogger().WithError(err).Warn("Failed to list links")
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

func LoadCgroupProgram(
	bpfDir, mapDir, ciliumDir string,
	load *Program) (error, int) {

	f, err := os.Open(fgsCgroupPath)
	if err != nil {
		return fmt.Errorf("failed to open '%s': %w", fgsCgroupPath, err), 0
	}
	defer f.Close()

	// TODO: Use AttachCgroup?
	return loadProgram(bpfDir, []string{mapDir, ciliumDir}, load, rawAttachWithProgram(int(f.Fd()))), 0
}

func installTailCalls(mapDir string, spec *ebpf.CollectionSpec, coll *ebpf.Collection) error {
	// FIXME(JM): This should be replaced by using the cilium/ebpf prog array initialization.

	secToProgName := make(map[string]string)
	for name, prog := range spec.Programs {
		secToProgName[prog.SectionName] = name
	}

	install := func(mapName string, secPrefix string) error {
		tailCallsMap, err := ebpf.LoadPinnedMap(filepath.Join(mapDir, mapName), nil)
		if err != nil {
			return nil
		}
		defer tailCallsMap.Close()

		for i := 0; i < 6; i++ {
			secName := fmt.Sprintf("%s/%d", secPrefix, i)
			if progName, ok := secToProgName[secName]; ok {
				if prog, ok := coll.Programs[progName]; ok {
					err := tailCallsMap.Update(uint32(i), uint32(prog.FD()), ebpf.UpdateAny)
					if err != nil {
						return fmt.Errorf("update of tail-call map '%s' failed: %w", mapName, err)
					}
				}
			}
		}
		return nil
	}

	if err := install("http1_calls", "sk_msg"); err != nil {
		return err
	}
	if err := install("http1_calls_skb", "sk_skb/stream_verdict"); err != nil {
		return err
	}
	if err := install("tls_calls", "classifier"); err != nil {
		return err
	}

	return nil
}

func SetFilter(mapDir string, mapName string, selectors [128]byte) error {
	selectorMap, err := ebpf.LoadPinnedMap(filepath.Join(mapDir, mapName), nil)
	if err != nil {
		return fmt.Errorf("failed to open selector map '%s': %w", mapName, err)
	}
	defer selectorMap.Close()

	return selectorMap.Update(uint32(0), selectors, ebpf.UpdateAny)
}

func loadProgram(
	bpfDir string,
	mapDirs []string,
	load *Program,
	withProgram WithProgramFunc,
) error {
	var btfFile *os.File
	if btfFilePath := btf.GetCachedBTFFile(); btfFilePath != "/sys/kernel/btf/vmlinux" {
		// Non-standard path to BTF, open it and provide it as 'TargetBTF'.
		var err error
		btfFile, err = os.Open(btfFilePath)
		if err != nil {
			return fmt.Errorf("opening BTF file '%s' failed: %w", btfFilePath, err)
		}
		defer btfFile.Close()
	}

	spec, err := ebpf.LoadCollectionSpec(load.Name)
	if err != nil {
		return fmt.Errorf("loading collection spec failed: %w", err)
	}

	var progSpec *ebpf.ProgramSpec

	// Find the program spec for the target program
	for _, prog := range spec.Programs {
		if prog.SectionName == load.Label {
			progSpec = prog
			break
		}
	}

	if progSpec == nil {
		return fmt.Errorf("program for section '%s' not found", load.Label)
	}

	// Find all the maps referenced by the program, so we'll rewrite only
	// the ones used.
	refMaps := make(map[string]bool)
	for _, inst := range progSpec.Instructions {
		if inst.Reference != "" {
			refMaps[inst.Reference] = true
		}
	}

	pinnedMaps := make(map[string]*ebpf.Map)
	for name := range refMaps {
		var m *ebpf.Map
		var err error
		for _, mapDir := range mapDirs {
			mapPath := filepath.Join(mapDir, name)
			m, err = ebpf.LoadPinnedMap(mapPath, nil)
			if err == nil {
				break
			}
		}
		if err == nil {
			defer m.Close()
			pinnedMaps[name] = m
		} else {
			logger.GetLogger().WithField("prog", load.Label).Debugf("pin file for map '%s' not found, map is not shared!\n", name)
		}
	}
	if err := spec.RewriteMaps(pinnedMaps); err != nil {
		return fmt.Errorf("rewrite maps failed: %w", err)
	}

	var opts ebpf.CollectionOptions
	if btfFile != nil {
		opts.Programs.TargetBTF = btfFile
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, opts)
	if err != nil {
		return fmt.Errorf("opening collection failed: %w", err)
	}
	defer coll.Close()

	err = installTailCalls(mapDirs[0], spec, coll)
	if err != nil {
		return fmt.Errorf("installing tail calls failed: %s", err)
	}

	prog, ok := coll.Programs[progSpec.Name]
	if !ok {
		return fmt.Errorf("program for section '%s' not found", load.Label)
	}

	pinPath := filepath.Join(bpfDir, load.PinPath)

	if _, err := os.Stat(pinPath); err == nil {
		logger.GetLogger().Warnf("Pin file '%s' already exists, repinning", load.PinPath)
		if err := os.Remove(pinPath); err != nil {
			logger.GetLogger().Warnf("Unpinning '%s' failed: %s", pinPath, err)
		}
	}

	if err := prog.Pin(pinPath); err != nil {
		return fmt.Errorf("pinning '%s' to '%s' failed: %w", load.Label, pinPath, err)
	}

	err = withProgram(prog, progSpec)
	if err != nil {
		return err
	}

	return nil
}
