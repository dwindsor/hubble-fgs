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
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/isovalent/hubble-fgs/pkg/api/fileapi"
)

func actToStr(act uint32) string {
	if act == FilterIgnore {
		return fmt.Sprintf("ignore(%d)", act)
	} else if act == FilterMatch {
		return fmt.Sprintf("match(%d)", act)
	} else if act == FilterMonitor {
		return fmt.Sprintf("monitor(%d)", act)
	}
	return fmt.Sprintf("unknown(%d)", act)
}

func PrintInodeMap(path string, filter func(key *fileapi.InodeKey, val *fileapi.InodeVal) bool) error {
	handle, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return fmt.Errorf("cannot open pinned map %s", path)
	}
	defer handle.Close()

	var key fileapi.InodeKey
	var val fileapi.InodeVal
	count := 0
	matched := 0
	entries := handle.Iterate()
	for entries.Next(&key, &val) {
		if filter(&key, &val) {
			if val.ContainerID[0] != 0x00 && val.ContainerID[1] != 0x00 {
				cid := string(val.ContainerID[:])
				fmt.Printf("ino[%7d],major[%3d],minor[%3d],action[%12s],cid[%s],path[%s]\n", key.Ino, key.DevMajor, key.DevMinor, actToStr(val.Action), cid, string(val.FullPath[:val.PathSize]))
			} else {
				fmt.Printf("ino[%7d],major[%3d],minor[%3d],action[%12s],path[%s]\n", key.Ino, key.DevMajor, key.DevMinor, actToStr(val.Action), string(val.FullPath[:val.PathSize]))
			}
			matched++
		}
		count++
	}

	fmt.Printf("Found %d (and printed %d) entries in %s map\n", count, matched, path)
	return nil
}

func PrintLPMMap(path string) error {
	handle, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return fmt.Errorf("cannot open pinned map %s", path)
	}
	defer handle.Close()

	var key fileapi.LPMMapKey
	var val fileapi.LPMMapValue
	entries := handle.Iterate()
	for entries.Next(&key, &val) {
		fmt.Printf("path[%s],action[%s]\n", string(key.Data[:(key.Prefixlen/8)]), actToStr(uint32(val.Action)))
	}

	return nil
}
