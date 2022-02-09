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
	"strings"

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
	tls_selectors [128]byte,
) (error, int) {
	return LoadCgroupProgram(bpfDir, mapDir, load, []Selector{{"tls_filter_map", tls_selectors}})
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

	return loadProgram(bpfDir, mapDir, load, targetMap.FD(), []Selector{})
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
	x64 bool,
	tls_selectors, http_selectors, nop_selectors [128]byte,
) (error, int) {
	if bpf.IsSockopsLoaded() {
		return nil, 0
	}
	bpf.CgroupSockopsRefInc()
	return LoadCgroupProgram(bpfDir, mapDir, load,
		[]Selector{
			{"tls_filter_map", tls_selectors},
			{"http_filter_map", http_selectors},
			{"nop_filter_map", nop_selectors},
		})
}

func LoadTC(
	bpfDir, mapDir, ciliumDir string,
	load *Program,
	version, verbose int,
	selectors [128]byte,
) (error, int) {
	var attachLinks []netlink.Link

	btfObj := uintptr(btf.GetCachedBTF())
	err, fd := bpf.LoadTC(
		version, verbose,
		btfObj,
		load.Name,
		load.Label,
		filepath.Join(bpfDir, load.PinPath),
		mapDir,
		ciliumDir,
		selectors,
	)
	if err != nil {
		return err, fd
	}
	attachLinks, err = getDefaultRouteLinks()
	if err != nil {
		return err, 0
	}

	for _, link := range attachLinks {
		logger.GetLogger().Infof("Attaching %s to device %s", load.Type, link.Attrs().Name)
		isIngress := "tc_ingress" == load.Type
		if err = bpf.QdiscTCInsert(link.Attrs().Name, isIngress); err != nil {
			return err, 0
		}
		bpf.AttachTCIngress(fd, link.Attrs().Name, isIngress)
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
	bpfDir, mapDir string,
	load *Program,
	selectors []Selector,
) (error, int) {

	f, err := os.Open(fgsCgroupPath)
	if err != nil {
		return fmt.Errorf("failed to open '%s': %w", fgsCgroupPath, err), 0
	}
	defer f.Close()

	// TODO: Use AttachCgroup?
	return loadProgram(bpfDir, mapDir, load, int(f.Fd()), selectors)
}

func installTailCalls(mapDir string, spec *ebpf.CollectionSpec, coll *ebpf.Collection) error {
	secToProgName := make(map[string]string)
	for name, prog := range spec.Programs {
		secToProgName[prog.SectionName] = name
	}

	install := func(mapName string, secPrefix string) error {
		tailCallsMap, err := ebpf.LoadPinnedMap(filepath.Join(mapDir, mapName), nil)
		if err != nil {
			return fmt.Errorf("failed to open map '%s': %w", mapName, err)
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

	return nil
}

func setFilter(mapDir string, mapName string, selectors [128]byte) error {
	selectorMap, err := ebpf.LoadPinnedMap(filepath.Join(mapDir, mapName), nil)
	if err != nil {
		return fmt.Errorf("failed to open selector map '%s': %w", mapName, err)
	}
	defer selectorMap.Close()

	return selectorMap.Update(uint32(0), selectors, ebpf.UpdateAny)
}

func loadProgram(
	bpfDir, mapDir string,
	load *Program,
	targetFD int,
	selectors []Selector,
) (err error, fd int) {
	var btfFile *os.File
	if btfFilePath := btf.GetCachedBTFFile(); btfFilePath != "/sys/kernel/btf/vmlinux" {
		// Non-standard path to BTF, open it and provide it as 'TargetBTF'.
		btfFile, err = os.Open(btfFilePath)
		if err != nil {
			return fmt.Errorf("opening BTF file '%s' failed: %w", btfFilePath, err), 0
		}
		defer btfFile.Close()
	}

	spec, err := ebpf.LoadCollectionSpec(load.Name)
	if err != nil {
		return fmt.Errorf("loading collection spec failed: %w", err), 0
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
		return fmt.Errorf("program for section '%s' not found", load.Label), 0
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
		mapPath := filepath.Join(mapDir, name)
		m, err := ebpf.LoadPinnedMap(mapPath, nil)
		if err == nil {
			defer m.Close()
			pinnedMaps[name] = m
		}
		// TODO(JM): Would be great to be more declarative about which
		// maps we need pinned and which can be program local.
	}
	if err := spec.RewriteMaps(pinnedMaps); err != nil {
		return fmt.Errorf("rewrite maps failed: %w", err), 0
	}

	var opts ebpf.CollectionOptions
	if btfFile != nil {
		opts.Programs.TargetBTF = btfFile
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, opts)
	if err != nil {
		return fmt.Errorf("opening collection failed: %w", err), 0
	}
	defer coll.Close()

	if strings.Contains(load.Name, "_http") {
		// TODO(JM): Use cilium/ebpf's prog array initialization and remove this.
		err = installTailCalls(mapDir, spec, coll)
		if err != nil {
			return fmt.Errorf("installing tail calls failed: %w", err), 0
		}
	}

	for _, selector := range selectors {
		if selectorMap, ok := coll.Maps[selector.MapName]; ok {
			if err = selectorMap.Update(uint32(0), selector.Selectors, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("selector install failed: %w", err), 0
			}
		} else {
			// TODO(JM): UDP sensor currently loads all programs with the "tls_filter_map" selector,
			// and this isn't in all of them. Properly fix the load in the UDP sensor.
			//return fmt.Errorf("selector '%s' not found from program '%s'", selector.MapName, load.Name), 0
			logger.GetLogger().Warnf("Selector '%s' not found from program '%s', ignoring.", selector.MapName, load.Name)
		}
	}

	prog, ok := coll.Programs[progSpec.Name]
	if !ok {
		return fmt.Errorf("program for section '%s' not found", load.Label), 0
	}

	pinPath := filepath.Join(bpfDir, load.PinPath)

	if _, err := os.Stat(pinPath); err == nil {
		logger.GetLogger().Warnf("Pin file '%s' already exists, repinning", load.PinPath)
		if err := os.Remove(pinPath); err != nil {
			logger.GetLogger().Warnf("Unpinning '%s' failed: %s", pinPath, err)
		}
	}

	if err := prog.Pin(pinPath); err != nil {
		return fmt.Errorf("pinning '%s' to '%s' failed: %w", load.Label, pinPath, err), 0
	}

	err = link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  targetFD,
		Program: prog,
		Attach:  progSpec.AttachType,
	})
	if err != nil {
		if err := prog.Unpin(); err != nil {
			logger.GetLogger().WithError(err).Warn("Failed to unpin program after failed attach")
		}
		return fmt.Errorf("attaching '%s' failed: %w", load.Label, err), 0
	}
	return nil, 0
}
