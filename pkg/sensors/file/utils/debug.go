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

func PrintInodeMap(path string, filter func(key *fileapi.HashMapFileKey, val *fileapi.HashMapFileVal) bool) error {
	handle, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return fmt.Errorf("cannot open pinned map %s", path)
	}
	defer handle.Close()

	var key fileapi.HashMapFileKey
	var val fileapi.HashMapFileVal
	count := 0
	matched := 0
	entries := handle.Iterate()
	for entries.Next(&key, &val) {
		if filter(&key, &val) {
			if val.ContainerID[0] != 0x00 && val.ContainerID[1] != 0x00 {
				cid := string(val.ContainerID[:])
				fmt.Printf("ino[%7d],major[%3d],minor[%3d],action[%d],cid[%s],path[%s]\n", key.Ino, key.DevMajor, key.DevMinor, val.Action, cid, string(val.FullPath[:val.PathSize]))
			} else {
				fmt.Printf("ino[%7d],major[%3d],minor[%3d],action[%d],path[%s]\n", key.Ino, key.DevMajor, key.DevMinor, val.Action, string(val.FullPath[:val.PathSize]))
			}
			matched++
		}
		count++
	}

	fmt.Printf("Found %d (and printed %d) entries in %s map\n", count, matched, path)
	return nil
}
