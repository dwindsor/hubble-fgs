// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package file

import (
	"fmt"
	"path"
	"strings"

	"github.com/cilium/ebpf"

	"github.com/cilium/tetragon/api/v1/tetragon"

	"github.com/isovalent/hubble-fgs/pkg/api/fileapi"
)

func actToStr(act uint32) string {
	switch act {
	case FilterIgnore:
		return fmt.Sprintf("ignore(%d)", act)
	case FilterMatch:
		return fmt.Sprintf("match(%d)", act)
	case FilterMonitor:
		return fmt.Sprintf("monitor(%d)", act)
	}
	return fmt.Sprintf("unknown(%d)", act)
}

func PrintFilenameDigestMaps(policyDir string) error {
	filenameMapPath := path.Join(policyDir, FilenamePathMapName)
	filenameHandle, err := ebpf.LoadPinnedMap(filenameMapPath, nil)
	if err != nil {
		return fmt.Errorf("cannot open pinned map %s", filenameMapPath)
	}
	defer filenameHandle.Close()

	fmt.Println("-------- Printing", filenameMapPath, "contents --------")

	filenameMapIter := filenameHandle.Iterate()
	var selIdx uint32
	var innerMapID ebpf.MapID
	for filenameMapIter.Next(&selIdx, &innerMapID) {
		innerMap, err := ebpf.NewMapFromID(innerMapID)
		if err != nil {
			return err
		}

		fmt.Println("Selector ID:", selIdx)

		innerIter := innerMap.Iterate()
		var path [256]byte
		var pathIdx uint32
		for innerIter.Next(&path, &pathIdx) {
			fmt.Printf("    path:[%s],pathID:[%d]\n", string(path[:]), pathIdx)
		}
	}

	digestsMapPath := path.Join(policyDir, FilenameDigestMapName)
	digestsHandle, err := ebpf.LoadPinnedMap(digestsMapPath, nil)
	if err != nil {
		return fmt.Errorf("cannot open pinned map %s", digestsMapPath)
	}
	defer digestsHandle.Close()

	fmt.Println("-------- Printing", digestsMapPath, "contents --------")

	digestsMapIter := digestsHandle.Iterate()
	for digestsMapIter.Next(&selIdx, &innerMapID) {
		innerMap, err := ebpf.NewMapFromID(innerMapID)
		if err != nil {
			return err
		}

		fmt.Println("Selector ID:", selIdx)

		innerIter := innerMap.Iterate()
		var digest fileapi.DigestKey
		var digestIdx uint32
		for innerIter.Next(&digest, &digestIdx) {
			digestLen := IMA_MAX_DIGEST_SIZE
			if dlen, ok := HashAlgoLen[tetragon.DigestAlgo(digest.Algo)]; ok {
				digestLen = dlen
			}
			var digestStr strings.Builder
			for i := range digestLen {
				fmt.Fprintf(&digestStr, "%02x", digest.Digest[i])
			}
			fmt.Printf("    digest:[%d, %d, %s],digestID:[%d]\n", digest.Ok, digest.Algo, digestStr.String(), digestIdx)
		}
	}
	return nil
}

func hashMapFileModeToStr(m uint16) string {
	switch m {
	case fileapi.HashMapFileModeFile:
		return "File"
	case fileapi.HashMapFileModeDirectory:
		return "Directory"
	case fileapi.HashMapFileModeSocket:
		return "Socket"
	}
	return "Unknown"
}

func inodeValSrcToStr(s uint16) string {
	switch s {
	case fileapi.InodeValSrcWalk:
		return "Walk"
	case fileapi.InodeValSrcWalkRename:
		return "WalkRename"
	case fileapi.InodeValSrcWalkPath:
		return "WalkPath"
	case fileapi.InodeValSrcEbpfRename:
		return "eBPFRename"
	case fileapi.InodeValSrcEbpfLink:
		return "eBPFLink"
	case fileapi.InodeValSrcEbpfMkdir:
		return "eBPFMkdir"
	case fileapi.InodeValSrcEbpfCreate:
		return "eBPFCreate"
	}
	return "Unknown"
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
				fmt.Printf("ino[%7d],major[%3d],minor[%3d],action[%12s],cid[%s],path[%s],mode[%s],src[%s]\n", key.Ino, key.DevMajor, key.DevMinor, actToStr(val.Action), cid, string(val.FullPath[:val.PathSize]), hashMapFileModeToStr(val.Mode), inodeValSrcToStr(val.Source))
			} else {
				fmt.Printf("ino[%7d],major[%3d],minor[%3d],action[%12s],path[%s],mode[%s],src[%s]\n", key.Ino, key.DevMajor, key.DevMinor, actToStr(val.Action), string(val.FullPath[:val.PathSize]), hashMapFileModeToStr(val.Mode), inodeValSrcToStr(val.Source))
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
