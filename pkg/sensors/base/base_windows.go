// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package base

import (
	"github.com/cilium/tetragon/pkg/sensors/program"
)

var (
	CreateProcess = program.Builder(
		"process_monitor.sys",
		"process",
		"ProcessMonitor",
		"process__program",
		"windows",
	).SetPolicy(basePolicy)

	ProcessRingBufMap = program.MapBuilder("process_ringbuf", CreateProcess)
	ProcessPidMap     = program.MapBuilder("process_map", CreateProcess)
	ProcessCmdMap     = program.MapBuilder("command_map", CreateProcess)
)

func GetDefaultPrograms() []*program.Program {
	progs := []*program.Program{
		CreateProcess,
	}
	return progs
}

func GetDefaultMaps() []*program.Map {
	maps := []*program.Map{
		ProcessRingBufMap,
		ProcessCmdMap,
		ProcessPidMap,
	}
	return maps

}
