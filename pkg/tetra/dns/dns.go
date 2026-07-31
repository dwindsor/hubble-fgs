// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package dns

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/cgroups"
	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/dnsparser"
)

func findAllocsIDs(ipMap dnsparser.IPToDomainMap) ([]uint32, error) {
	allocIDs := []uint32{}
	for ids := range uint32(dnsparser.MaxNumberOfPods) {
		exist, err := ipMap.InnerMapExist(ids)
		if err != nil {
			return nil, fmt.Errorf("failed finding if inner map exist: %w", err)
		}
		if !exist {
			continue
		}
		allocIDs = append(allocIDs, ids)
	}
	return allocIDs, nil
}

func FindSubDirs(root string) ([]string, error) {
	var dirs []string
	f, err := os.Open(root)
	if err != nil {
		return nil, err
	}
	fileInfo, err := f.Readdir(-1)
	f.Close()
	if err != nil {
		return nil, err
	}

	for _, file := range fileInfo {
		if file.IsDir() {
			dirs = append(dirs, file.Name())
		}
	}
	return dirs, nil
}

func getPIDsFromCgroupV2(path string) ([]int, error) {
	f, err := os.Open(filepath.Join(path, "cgroup.procs"))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pids []int
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if pid, err := strconv.Atoi(sc.Text()); err == nil {
			// PID 0 should be ignored
			if pid == 0 {
				continue
			}
			pids = append(pids, pid)
		}
	}
	return pids, sc.Err()
}

func getExeBase(pid int) (string, error) {
	link, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	if err != nil {
		return "", err
	}
	return filepath.Base(link), nil
}

func getCgroupIDToAllocID() (map[uint64]uint32, error) {
	mapPath := bpf.MapPath(dnsparser.CgroupIDToAllocIDMapName)
	mapRaw, err := ebpf.LoadPinnedMap(mapPath, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to load the cgroup ID to alloc ID map: %w", err)
	}
	defer mapRaw.Close()
	m := dnsparser.NewCgroupIDToAllocIDMap(mapRaw)
	cgroupIDToAllocID, err := m.Values()
	if err != nil {
		return nil, fmt.Errorf("failed to get the values from the cgroup ID to alloc ID map: %w", err)
	}
	return cgroupIDToAllocID, nil
}

func findCgroupPIDsByVisiting[K any](cgroupIDs map[uint64]K) (map[uint64][]int, error) {
	rootPath, err := cgroups.HostCgroupRoot()
	if err != nil {
		return nil, fmt.Errorf("failed to find the host cgroup root: %w", err)
	}

	done := errors.New("found target file")
	cgroupIDToPIDs := map[uint64][]int{}
	err = filepath.WalkDir(rootPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if !d.IsDir() {
			return nil
		}

		cgroupID, err := cgroups.GetCgroupIdFromPath(path)
		if err != nil {
			return fmt.Errorf("failed retrieving the cgroup ID from path: %w", err)
		}

		if _, found := cgroupIDs[cgroupID]; found {
			pids, err := getPIDsFromCgroupV2(path)
			if err != nil {
				return fmt.Errorf("failed retrieving PIDs from the cgroup path %s: %w", path, err)
			}

			// visit the direct subdirectories
			subdirs, err := FindSubDirs(path)
			if err != nil {
				return fmt.Errorf("failed to list subdir of cgroup path %s: %w", path, err)
			}
			for _, subdir := range subdirs {
				subPids, err := getPIDsFromCgroupV2(filepath.Join(path, subdir))
				if err != nil {
					return fmt.Errorf("failed retrieving PIDs from the cgroup path %s: %w", subdir, err)
				}
				pids = append(pids, subPids...)
			}

			cgroupIDToPIDs[cgroupID] = pids

			// we already visited the direct subdirectories (we
			// don't support more nested cgroup) so we skip this
			// branch
			return filepath.SkipDir
		}

		if len(cgroupIDToPIDs) == len(cgroupIDs) {
			return done
		}

		return nil
	})

	if err != nil && !errors.Is(err, done) {
		return nil, fmt.Errorf("failed walking the cgroup hierarchy: %w", err)
	}

	return cgroupIDToPIDs, nil
}

func NewDNSCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "dns [mapID]",
		Short: "Debug the DNS BPF parser IP to domain map.",
		Long: `Debug the DNS BPF parser IP to domain map. You can give a mapID as argument to
print the appropriate map or let the command discover the available one for you.

Examples:
  # Print all available maps
  tetra debug dns

  # Print the map with ID 3
  tetra debug dns 3`,
		RunE: func(cmd *cobra.Command, args []string) error {
			allocIDs := []uint32{}
			if len(args) > 0 {
				largeMapID, err := strconv.Atoi(args[0])
				if err != nil {
					return fmt.Errorf("failed to parse map ID arg %q: %w", args[0], err)
				}
				if largeMapID > math.MaxUint32 {
					return fmt.Errorf("invalid map ID, %d is > to max uint32", largeMapID)
				}
				allocIDs = append(allocIDs, uint32(largeMapID))
			}

			ipMap, err := dnsparser.LoadNewIPToDomainMap()
			if err != nil {
				return fmt.Errorf("fail to load ip map: %w", err)
			}
			defer ipMap.Close()

			if len(allocIDs) == 0 {
				allocIDs, err = findAllocsIDs(ipMap)
				if err != nil {
					return fmt.Errorf("failed to discover the allocation IDs: %w", err)
				}
			}

			cgroupIDToAllocID, err := getCgroupIDToAllocID()
			if err != nil {
				return err
			}

			// Create the reverse map
			allocIDToCgroupID := map[uint32]uint64{}
			for cgroupID, allocID := range cgroupIDToAllocID {
				allocIDToCgroupID[allocID] = cgroupID
			}

			// Search the corresponding PIDs from the cgroupIDs
			cgroupIDToPIDs, err := findCgroupPIDsByVisiting(cgroupIDToAllocID)
			if err != nil {
				// let's just skip this if we fail for whatever reason
				cmd.PrintErr(fmt.Errorf("warning: failed to find the PIDs from Cgroup IDs: %w", err))
			}

			for _, mapID := range allocIDs {
				// First print an info on mapID, cgroupID and the PIDs in the cgroup
				var cgInfo strings.Builder
				cgroupID := allocIDToCgroupID[mapID]
				fmt.Fprintf(&cgInfo, "MapID:%d CgroupID:%d", mapID, cgroupID)
				if len(cgroupIDToPIDs[cgroupID]) != 0 {
					fmt.Fprint(&cgInfo, " PIDs:")
				}
				for i, pid := range cgroupIDToPIDs[cgroupID] {
					exeBase, err := getExeBase(pid)
					if err != nil {
						// do not return an error here, just try your best
						cmd.PrintErr(fmt.Errorf("failed retrieving exe base for pid %d: %w", pid, err))
					}
					fmt.Fprintf(&cgInfo, "%d(%s)", pid, exeBase)
					if i < len(cgroupIDToPIDs[cgroupID])-1 {
						fmt.Fprint(&cgInfo, ",")
					}
				}
				cmd.Println(cgInfo.String())

				// Then print the actual array of IP and domain
				values, err := ipMap.Values(mapID)
				if err != nil {
					return fmt.Errorf("failed retrieving values: %w", err)
				}

				w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 3, ' ', 0)
				fmt.Fprintln(w, "IP\tDOMAIN\t")
				for ip, domain := range values {
					fmt.Fprintf(w, "%s\t%s\n", ip, domain)
				}
				err = w.Flush()
				if err != nil {
					return fmt.Errorf("failed to flush writer: %w", err)
				}

				// Add a newline for multiple arrays if not reaching the end
				if len(allocIDs) > 1 && mapID != uint32(len(allocIDs)) {
					cmd.Println()
				}
			}

			return nil
		},
	}
}
