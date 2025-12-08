//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package exec

import (
	"errors"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"golang.org/x/sys/windows"
)

var (
	cmd_map   *ebpf.Map
	image_map *ebpf.Map
)

func getArgsFromPID(PID uint32) (string, string, error) {

	if (cmd_map == nil) || (image_map == nil) {
		coll, _ := bpf.GetCollection("ProcessMonitor")
		if coll == nil {
			return "", "", errors.New("exec Preloaded collection is nil")
		}
		var ok bool
		cmd_map, ok = coll.Maps["command_map"]
		if !ok {
			return "", "", errors.New("commad_map not found or not pinned")
		}
		image_map, ok = coll.Maps["process_map"]
		if !ok {
			return "", "", errors.New("commad_map not found or not pinned")
		}
	}
	var wideCmd [2048]uint16
	cmd_map.Lookup(PID, &wideCmd)

	strCmd := windows.UTF16ToString(wideCmd[:])

	var wideImagePath [1024]byte
	image_map.Lookup(PID, &wideImagePath)

	var s = (*uint16)(unsafe.Pointer(&wideImagePath[0]))
	strImagePath := windows.UTF16PtrToString(s)

	strImagePath = strings.TrimPrefix(strImagePath, "\\??\\")
	stringToTrim := strImagePath

	if strings.HasPrefix(strCmd, "\"") {
		stringToTrim = "\"" + stringToTrim + "\""
	}
	strCmd = strings.TrimPrefix(strCmd, stringToTrim)
	strCmd = strings.TrimPrefix(strCmd, " ")
	return strImagePath, strCmd, nil

}
